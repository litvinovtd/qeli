//! Linux TUN/TAP packet backend for the shared client core.
//!
//! The TCP and UDP transports consume and produce IP packets. This backend alone owns
//! the duplicated TUN file descriptors, blocking workers, bounded queues and TAP framing,
//! so reconnect teardown has one implementation independent of the selected wire mode.

use crate::tun::{prepend_ethernet_header, strip_ethernet_header};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;

const FROM_TUN_CAPACITY: usize = 4096;
const TO_TUN_CAPACITY: usize = 2048;
const POLL_TIMEOUT_MS: i32 = 250;
const WRITER_STOP_POLL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy)]
pub struct TapHeaders {
    pub client_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
}

#[derive(Debug, Clone, Copy)]
pub struct LinuxTunPumpConfig {
    pub buffer_size: usize,
    pub tap: Option<TapHeaders>,
}

/// Cloneable, non-owning cancellation handle used by the platform teardown guard.
#[derive(Clone)]
pub struct LinuxTunPumpStop(Arc<AtomicBool>);

impl LinuxTunPumpStop {
    pub fn request_stop(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Owns the Linux TUN packet workers and their queues for one connection generation.
pub struct LinuxTunPump {
    from_tun: mpsc::Receiver<Vec<u8>>,
    to_tun: Option<std_mpsc::SyncSender<Vec<u8>>>,
    stop: LinuxTunPumpStop,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl LinuxTunPump {
    pub fn start(
        reader_fd: OwnedFd,
        writer_fd: OwnedFd,
        config: LinuxTunPumpConfig,
    ) -> io::Result<Self> {
        if config.buffer_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN buffer size must be non-zero",
            ));
        }

        let stop = LinuxTunPumpStop(Arc::new(AtomicBool::new(false)));
        let (from_tun_tx, mut from_tun) = mpsc::channel(FROM_TUN_CAPACITY);
        let (to_tun_tx, to_tun_rx) = std_mpsc::sync_channel(TO_TUN_CAPACITY);

        let reader_stop = stop.clone();
        let reader = std::thread::Builder::new()
            .name("qeli-tun-reader".into())
            .spawn(move || reader_loop(reader_fd, from_tun_tx, reader_stop, config))?;

        let writer_stop = stop.clone();
        let writer = match std::thread::Builder::new()
            .name("qeli-tun-writer".into())
            .spawn(move || writer_loop(writer_fd, to_tun_rx, writer_stop, config.tap))
        {
            Ok(writer) => writer,
            Err(error) => {
                stop.request_stop();
                from_tun.close();
                drop(to_tun_tx);
                let _ = reader.join();
                return Err(error);
            }
        };

        Ok(Self {
            from_tun,
            to_tun: Some(to_tun_tx),
            stop,
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    pub fn stop_handle(&self) -> LinuxTunPumpStop {
        self.stop.clone()
    }

    pub fn sender_to_tun(&self) -> std_mpsc::SyncSender<Vec<u8>> {
        self.to_tun
            .as_ref()
            .expect("TUN sender is unavailable after shutdown")
            .clone()
    }

    pub async fn recv_from_tun(&mut self) -> Option<Vec<u8>> {
        self.from_tun.recv().await
    }

    /// Stop both workers, close their descriptors and wait until ownership is released.
    pub async fn shutdown(mut self) {
        self.request_stop();
        let reader = self.reader.take();
        let writer = self.writer.take();
        if reader.is_none() && writer.is_none() {
            return;
        }
        let joined = tokio::task::spawn_blocking(move || {
            if let Some(reader) = reader {
                let _ = reader.join();
            }
            if let Some(writer) = writer {
                let _ = writer.join();
            }
        })
        .await;
        if let Err(error) = joined {
            log::warn!("TUN worker join failed: {error}");
        }
    }

    fn request_stop(&mut self) {
        self.stop.request_stop();
        self.from_tun.close();
        self.to_tun.take();
    }
}

impl Drop for LinuxTunPump {
    fn drop(&mut self) {
        // Error paths cannot await, but closing both queues plus the stop flag makes the
        // detached workers release their OwnedFd values within one bounded poll interval.
        self.request_stop();
    }
}

fn reader_loop(
    reader_fd: OwnedFd,
    from_tun: mpsc::Sender<Vec<u8>>,
    stop: LinuxTunPumpStop,
    config: LinuxTunPumpConfig,
) {
    log::info!("TUN reader started");
    let mut buffer = vec![0u8; config.buffer_size];
    loop {
        if stop.0.load(Ordering::Acquire) {
            break;
        }
        let read = unsafe {
            libc::read(
                reader_fd.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {
                    let mut poll_fd = libc::pollfd {
                        fd: reader_fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let poll_result = unsafe { libc::poll(&mut poll_fd, 1, POLL_TIMEOUT_MS) };
                    if poll_result < 0
                        && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                    {
                        log::warn!("TUN poll error: {}", io::Error::last_os_error());
                        break;
                    }
                    continue;
                }
                _ => {
                    log::error!("TUN read error: {error}");
                    break;
                }
            }
        }
        if read == 0 {
            break;
        }

        let raw = &buffer[..read as usize];
        let packet = match config.tap {
            Some(_) => match strip_ethernet_header(raw) {
                Some(ip) => ip.to_vec(),
                None => continue,
            },
            None => raw.to_vec(),
        };
        if from_tun.blocking_send(packet).is_err() {
            break;
        }
    }
    log::info!("TUN reader stopped");
}

fn writer_loop(
    writer_fd: OwnedFd,
    to_tun: std_mpsc::Receiver<Vec<u8>>,
    stop: LinuxTunPumpStop,
    tap: Option<TapHeaders>,
) {
    log::info!("TUN writer started");
    'writer: loop {
        if stop.0.load(Ordering::Acquire) {
            break;
        }
        let packet = match to_tun.recv_timeout(WRITER_STOP_POLL) {
            Ok(packet) => packet,
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                if stop.0.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if packet.is_empty() {
            continue;
        }

        let tap_frame = tap.map(|headers| {
            prepend_ethernet_header(&packet, &headers.client_mac, &headers.gateway_mac)
        });
        let buffer = tap_frame.as_deref().unwrap_or(&packet);
        loop {
            let written = unsafe {
                libc::write(
                    writer_fd.as_raw_fd(),
                    buffer.as_ptr() as *const libc::c_void,
                    buffer.len(),
                )
            };
            if written >= 0 {
                if written as usize != buffer.len() {
                    log::warn!(
                        "TUN writer accepted only {written} of {} packet bytes",
                        buffer.len()
                    );
                }
                break;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ENOBUFS) | Some(libc::EAGAIN) => {
                    log::debug!("TUN writer dropped packet ({error})");
                    break;
                }
                _ => {
                    log::warn!("TUN writer fatal write error ({error}) - stopping");
                    break 'writer;
                }
            }
        }
    }
    log::info!("TUN writer stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    fn packet_pair() -> (UnixDatagram, OwnedFd) {
        let (test_end, pump_end) = UnixDatagram::pair().unwrap();
        pump_end.set_nonblocking(true).unwrap();
        (test_end, pump_end.into())
    }

    #[tokio::test]
    async fn pumps_packets_in_both_directions() {
        let (reader_test, reader_fd) = packet_pair();
        let (writer_test, writer_fd) = packet_pair();
        writer_test
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut pump = LinuxTunPump::start(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                tap: None,
            },
        )
        .unwrap();

        let uplink = [0x45, 0, 0, 20, 1, 2, 3, 4];
        reader_test.send(&uplink).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .expect("TUN reader did not forward a packet")
            .expect("TUN reader stopped unexpectedly");
        assert_eq!(received, uplink);

        let downlink = vec![0x60, 0, 0, 0, 5, 6, 7, 8];
        pump.sender_to_tun().send(downlink.clone()).unwrap();
        let mut received = [0u8; 64];
        let count = writer_test.recv(&mut received).unwrap();
        assert_eq!(&received[..count], downlink);

        pump.shutdown().await;
    }

    #[tokio::test]
    async fn tap_mode_strips_and_restores_ethernet_headers() {
        let (reader_test, reader_fd) = packet_pair();
        let (writer_test, writer_fd) = packet_pair();
        writer_test
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let headers = TapHeaders {
            client_mac: [2, 0, 0, 0, 0, 2],
            gateway_mac: [2, 0, 0, 0, 0, 1],
        };
        let mut pump = LinuxTunPump::start(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                tap: Some(headers),
            },
        )
        .unwrap();
        let ip_packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let frame = prepend_ethernet_header(&ip_packet, &headers.gateway_mac, &headers.client_mac);
        reader_test.send(&frame).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .expect("TAP reader did not forward an IP packet")
            .expect("TAP reader stopped unexpectedly");
        assert_eq!(received, ip_packet);

        pump.sender_to_tun().send(ip_packet.clone()).unwrap();
        let mut received = [0u8; 128];
        let count = writer_test.recv(&mut received).unwrap();
        assert_eq!(
            &received[..count],
            prepend_ethernet_header(&ip_packet, &headers.client_mac, &headers.gateway_mac,)
        );

        pump.shutdown().await;
    }

    #[tokio::test]
    async fn idle_shutdown_releases_both_descriptors() {
        let (_reader_test, reader_fd) = packet_pair();
        let (_writer_test, writer_fd) = packet_pair();
        let pump = LinuxTunPump::start(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                tap: None,
            },
        )
        .unwrap();

        tokio::time::timeout(Duration::from_secs(1), pump.shutdown())
            .await
            .expect("idle TUN workers did not stop within their bounded poll interval");
    }
}
