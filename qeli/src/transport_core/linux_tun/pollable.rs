//! Linux raw-IP reads on the transport's runtime: no reader-thread packet handoff.
//! Buffer loans must survive select cancellation and retain the same fixed budget.
use super::{LinuxTunPumpStop, TunPacket, READER_BUFFER_POLL};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use tokio::io::{unix::AsyncFd, Interest};
use tokio::sync::Notify;

pub(super) struct Reader {
    fd: Option<AsyncFd<OwnedFd>>,
    recycle: mpsc::SyncSender<Vec<u8>>,
    available: mpsc::Receiver<Vec<u8>>,
    returned: Arc<Notify>,
    stop: LinuxTunPumpStop,
}

impl Reader {
    pub(super) fn new(
        fd: OwnedFd,
        recycle: mpsc::SyncSender<Vec<u8>>,
        available: mpsc::Receiver<Vec<u8>>,
        stop: LinuxTunPumpStop,
        runtime: tokio::runtime::Handle,
    ) -> io::Result<Self> {
        // Startup runs on an owning network worker, outside the runtime thread.
        let _entered = runtime.enter();
        // SAFETY: AsyncFd exclusively owns this OwnedFd. Only shared borrows
        // reach read(); nothing closes or replaces its inner descriptor while
        // registered, and AsyncFd deregisters before OwnedFd is dropped.
        let fd = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }.map_err(
            |failure| {
                let (fd, error) = failure.into_parts();
                // Do not retain the failed descriptor inside an error past rollback.
                drop(fd);
                error
            },
        )?;
        log::info!("TUN reader registered with the transport runtime");
        Ok(Self {
            fd: Some(fd),
            recycle,
            available,
            returned: Arc::new(Notify::new()),
            stop,
        })
    }

    fn stopped(&self) -> bool {
        self.fd.is_none() || self.stop.0.load(Ordering::Acquire)
    }

    fn packet(&self, buffer: Vec<u8>) -> TunPacket {
        let mut packet = TunPacket::new(buffer, 0..0, self.recycle.clone());
        packet.on_recycle = Some(self.returned.clone());
        packet
    }

    fn read(&self, packet: &mut TunPacket) -> io::Result<usize> {
        let buffer = packet
            .buffer
            .as_mut()
            .expect("read loan retains its buffer");
        self.fd
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?
            .try_io(Interest::READABLE, |fd| {
                // SAFETY: the owned descriptor remains registered for this call. The
                // exclusive loan is initialized and writable for its complete length.
                let read =
                    unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if read < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(read as usize)
                }
            })
    }

    fn failed(&mut self, error: Option<io::Error>) {
        if let Some(error) = error {
            log::warn!("TUN read failed: {error}");
        }
        self.fd.take();
    }

    pub(super) fn try_recv(&mut self) -> Result<TunPacket, tokio::sync::mpsc::error::TryRecvError> {
        use tokio::sync::mpsc::error::TryRecvError::{Disconnected, Empty};
        if self.stopped() {
            return Err(Disconnected);
        }
        let buffer = self.available.try_recv().map_err(|e| match e {
            mpsc::TryRecvError::Empty => Empty,
            mpsc::TryRecvError::Disconnected => Disconnected,
        })?;
        let mut packet = self.packet(buffer);
        loop {
            match self.read(&mut packet) {
                Ok(0) => {
                    self.failed(None);
                    return Err(Disconnected);
                }
                Ok(n) => {
                    packet.range = 0..n;
                    return Ok(packet);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(Empty),
                Err(e) => {
                    self.failed(Some(e));
                    return Err(Disconnected);
                }
            }
        }
    }

    pub(super) async fn recv(&mut self) -> Option<TunPacket> {
        // Like Tokio's receiver, charge only a completed read to the task budget.
        // Pending/cancelled reads restore the budget and retain no consumed packet.
        tokio::task::coop::cooperative(self.recv_inner()).await
    }

    async fn recv_inner(&mut self) -> Option<TunPacket> {
        let mut packet = loop {
            if self.stopped() {
                return None;
            }
            match self.available.try_recv() {
                Ok(buffer) => break self.packet(buffer),
                Err(mpsc::TryRecvError::Disconnected) => return None,
                Err(mpsc::TryRecvError::Empty) => {
                    // One receiver: notify_one retains a permit if return races
                    // the check. A timeout also bounds an external stop request.
                    let _ =
                        tokio::time::timeout(READER_BUFFER_POLL, self.returned.notified()).await;
                }
            }
        };
        loop {
            if self.stopped() {
                return None;
            }
            match self.read(&mut packet) {
                Ok(0) => {
                    self.failed(None);
                    return None;
                }
                Ok(n) => {
                    packet.range = 0..n;
                    return Some(packet);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let readiness =
                        tokio::time::timeout(READER_BUFFER_POLL, self.fd.as_ref()?.readable())
                            .await
                            .map(|result| result.map(drop));
                    match readiness {
                        Ok(Ok(())) => (),
                        Ok(Err(e)) => {
                            self.failed(Some(e));
                            return None;
                        }
                        Err(_) => (),
                    }
                }
                Err(e) => {
                    self.failed(Some(e));
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{LinuxTunPump, LinuxTunPumpConfig, ReadBackend, TunFraming};
    use super::*;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    fn pump(slots: usize) -> (UnixDatagram, UnixDatagram, LinuxTunPump) {
        let (input, read) = UnixDatagram::pair().unwrap();
        let (output, write) = UnixDatagram::pair().unwrap();
        output
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let pump = LinuxTunPump::start_with_backend(
            read.into(),
            write.into(),
            LinuxTunPumpConfig {
                buffer_size: 2048,
                framing: TunFraming::Raw,
                downlink_record_bytes: 2048,
                write_drops: None,
            },
            slots,
            ReadBackend::Pollable(tokio::runtime::Handle::current()),
        )
        .unwrap();
        assert!(pump.pollable_from_tun.is_some());
        (input, output, pump)
    }

    #[tokio::test]
    async fn raw_packets_and_writer_preserve_order_and_bytes() {
        let (input, output, mut pump) = pump(2);
        for packet in [&[0x45, 1][..], &[0x60, 2][..]] {
            input.send(packet).unwrap();
            let received = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&*received, packet);
        }
        let writer = pump.sender_to_tun();
        let mut packet = writer.acquire().await.unwrap();
        let mut expected = [0u8; 40];
        expected[0] = 0x60;
        expected[1] = 3;
        expected[6] = 59;
        expected[7] = 64;
        packet.as_vec_mut().extend_from_slice(&expected);
        writer.try_send(packet).unwrap();
        let mut bytes = [0; 64];
        assert_eq!(output.recv(&mut bytes).unwrap(), 40);
        assert_eq!(&bytes[..40], &expected);
        pump.shutdown().await;
        assert!(input.send(&[1]).is_err());
        assert!(output.send(&[1]).is_err());
    }

    #[tokio::test]
    async fn cancelling_pending_reads_does_not_exhaust_the_pool() {
        let (input, _output, mut pump) = pump(2);
        for sequence in 0..16 {
            assert!(
                tokio::time::timeout(Duration::from_millis(2), pump.recv_from_tun())
                    .await
                    .is_err()
            );
            input.send(&[0x45, sequence]).unwrap();
            let packet = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&*packet, &[0x45, sequence]);
        }
        input.send(&[0x45, 7]).unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&*packet, &[0x45, 7]);
        drop(packet);
        pump.shutdown().await;
    }

    #[tokio::test]
    async fn checked_out_buffers_bound_reading_and_wake_after_return() {
        let (input, _output, mut pump) = pump(2);
        for sequence in 1..=3 {
            input.send(&[0x45, sequence]).unwrap();
        }
        let first = pump.recv_from_tun().await.unwrap();
        let second = pump.recv_from_tun().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pump.recv_from_tun())
                .await
                .is_err()
        );
        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&*second, &[0x45, 2]);
        assert_eq!(&*third, &[0x45, 3]);
        pump.shutdown().await;
        // Loans can safely outlive their stopped reader.
        drop(second);
        drop(third);
    }

    #[tokio::test]
    async fn external_stop_terminates_an_idle_read() {
        let (input, output, mut pump) = pump(2);
        let stop = pump.stop_handle();
        let stopper = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            stop.request_stop();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(500), pump.recv_from_tun())
                .await
                .unwrap()
                .is_none()
        );
        stopper.await.unwrap();
        pump.shutdown().await;
        assert!(input.send(&[1]).is_err());
        assert!(output.send(&[1]).is_err());
    }

    #[tokio::test]
    async fn registration_failure_closes_the_writer_descriptor() {
        let (output, write) = UnixDatagram::pair().unwrap();
        let reader = std::fs::File::open("/dev/null").unwrap();
        let result = LinuxTunPump::start_pollable(
            reader.into(),
            write.into(),
            LinuxTunPumpConfig {
                buffer_size: 2048,
                framing: TunFraming::Raw,
                downlink_record_bytes: 2048,
                write_drops: None,
            },
            tokio::runtime::Handle::current(),
        );
        assert!(result.is_err());
        assert!(output.send(&[1]).is_err());
    }

    #[test]
    fn cancelled_shutdown_closes_descriptors_without_runtime_progress() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (started, ready) = tokio::sync::oneshot::channel();
            let (unblock, waiting) = mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                let _ = waiting.recv_timeout(Duration::from_secs(5));
            });
            ready.await.unwrap();
            let (input, output, pump) = pump(2);
            let mut shutdown = Box::pin(pump.shutdown());
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(shutdown.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(shutdown);
            assert!(input.send(&[1]).is_err());
            assert!(output.send(&[1]).is_err());
            assert!(!blocker.is_finished());
            drop(unblock);
            blocker.await.unwrap();
        });
    }
}
