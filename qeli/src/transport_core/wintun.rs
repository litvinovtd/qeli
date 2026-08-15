//! Rust-owned Wintun session and packet rings for the Windows whole-client core.
//!
//! C# creates the adapter and keeps its creator handle only for interface lifetime and
//! route/DNS cleanup. This backend opens a second handle by name after the authenticated
//! network plan is applied, owns the session/read event, and is the only code that touches
//! packet bytes in the Wintun rings.

use super::buffer_pool::{BufferPool, PooledBuffer};
use super::packet_tun::PacketTunPump;
pub(crate) use super::packet_tun::TunWriter;
use std::ffi::c_void;
use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;

const RING_CAPACITY: u32 = 0x0040_0000;
const MAX_PACKET_BYTES: usize = 65_535;
const FROM_WINTUN_CAPACITY: usize = 4096;
const TO_WINTUN_CAPACITY: usize = 2048;
const DOWNLINK_POOL_BYTES: usize = 4 * 1024 * 1024;
const MIN_DOWNLINK_BUFFERS: usize = 4;
/// Slot-count ceiling, matched to the queue it feeds. Raised from 256 alongside the
/// record-sized slots below: with a 65 KiB slot the 4 MiB budget bought only 64 buffers —
/// a quarter of what the Android pump had, for the same reason (the reservation was the
/// protocol maximum, not the packet size), and 64 buffers is a few milliseconds of traffic
/// on a fast link, so any stall in the Wintun writer dropped inbound packets.
const MAX_DOWNLINK_BUFFERS: usize = TO_WINTUN_CAPACITY;
/// Floor for a record-derived slot, so a bogus MTU cannot produce useless slivers.
const MIN_DOWNLINK_SLOT_BYTES: usize = 2 * 1024;
const WRITER_STOP_POLL: Duration = Duration::from_millis(100);
const READ_WAIT_MS: u32 = 250;

const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = u32::MAX;

type OpenAdapter = unsafe extern "system" fn(*const u16) -> *mut c_void;
type CloseAdapter = unsafe extern "system" fn(*mut c_void);
type StartSession = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSession = unsafe extern "system" fn(*mut c_void);
type GetReadWaitEvent = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
type ReceivePacket = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(*mut c_void, *const u8);
type AllocateSendPacket = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(*mut c_void, *const u8);

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(module_name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
}

#[derive(Clone, Copy)]
struct WintunApi {
    open_adapter: OpenAdapter,
    close_adapter: CloseAdapter,
    start_session: StartSession,
    end_session: EndSession,
    get_read_wait_event: GetReadWaitEvent,
    receive_packet: ReceivePacket,
    release_receive_packet: ReleaseReceivePacket,
    allocate_send_packet: AllocateSendPacket,
    send_packet: SendPacket,
}

impl WintunApi {
    fn load() -> io::Result<Self> {
        let module_name: Vec<u16> = "wintun.dll".encode_utf16().chain(Some(0)).collect();
        let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
        if module.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "wintun.dll is not loaded by the platform adapter",
            ));
        }

        unsafe {
            Ok(Self {
                open_adapter: resolve(module, b"WintunOpenAdapter\0")?,
                close_adapter: resolve(module, b"WintunCloseAdapter\0")?,
                start_session: resolve(module, b"WintunStartSession\0")?,
                end_session: resolve(module, b"WintunEndSession\0")?,
                get_read_wait_event: resolve(module, b"WintunGetReadWaitEvent\0")?,
                receive_packet: resolve(module, b"WintunReceivePacket\0")?,
                release_receive_packet: resolve(module, b"WintunReleaseReceivePacket\0")?,
                allocate_send_packet: resolve(module, b"WintunAllocateSendPacket\0")?,
                send_packet: resolve(module, b"WintunSendPacket\0")?,
            })
        }
    }
}

unsafe fn resolve<T: Copy>(module: *mut c_void, name: &'static [u8]) -> io::Result<T> {
    let address = unsafe { GetProcAddress(module, name.as_ptr()) };
    if address.is_null() {
        let symbol = String::from_utf8_lossy(&name[..name.len().saturating_sub(1)]);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("wintun.dll does not export {symbol}"),
        ));
    }
    if std::mem::size_of::<T>() != std::mem::size_of_val(&address) {
        return Err(io::Error::other("Wintun function pointer size mismatch"));
    }
    Ok(unsafe { std::mem::transmute_copy(&address) })
}

fn last_error(operation: &str) -> io::Error {
    let code = unsafe { GetLastError() };
    io::Error::other(format!("{operation} failed (Windows error {code})"))
}

struct WintunSession {
    api: WintunApi,
    adapter: usize,
    session: usize,
    read_event: usize,
}

impl WintunSession {
    fn open(adapter_name: &str) -> io::Result<Self> {
        if adapter_name.is_empty() || adapter_name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Wintun adapter name is empty or contains NUL",
            ));
        }
        let api = WintunApi::load()?;
        let wide_name: Vec<u16> = adapter_name.encode_utf16().chain(Some(0)).collect();
        let adapter = unsafe { (api.open_adapter)(wide_name.as_ptr()) };
        if adapter.is_null() {
            return Err(last_error("WintunOpenAdapter"));
        }
        let session = unsafe { (api.start_session)(adapter, RING_CAPACITY) };
        if session.is_null() {
            let error = last_error("WintunStartSession");
            unsafe { (api.close_adapter)(adapter) };
            return Err(error);
        }
        let read_event = unsafe { (api.get_read_wait_event)(session) };
        if read_event.is_null() {
            let error = last_error("WintunGetReadWaitEvent");
            unsafe {
                (api.end_session)(session);
                (api.close_adapter)(adapter);
            }
            return Err(error);
        }
        Ok(Self {
            api,
            adapter: adapter as usize,
            session: session as usize,
            read_event: read_event as usize,
        })
    }

    fn receive(&self, packet_size: &mut u32) -> *mut u8 {
        unsafe { (self.api.receive_packet)(self.session as *mut c_void, packet_size) }
    }

    fn release(&self, packet: *const u8) {
        unsafe { (self.api.release_receive_packet)(self.session as *mut c_void, packet) }
    }
}

impl Drop for WintunSession {
    fn drop(&mut self) {
        unsafe {
            (self.api.end_session)(self.session as *mut c_void);
            (self.api.close_adapter)(self.adapter as *mut c_void);
        }
    }
}

pub(crate) struct WintunPacket {
    pointer: usize,
    length: usize,
    session: Arc<WintunSession>,
}

impl Deref for WintunPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.pointer as *const u8, self.length) }
    }
}

impl AsRef<[u8]> for WintunPacket {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for WintunPacket {
    fn drop(&mut self) {
        self.session.release(self.pointer as *const u8);
    }
}

pub(crate) struct WintunPump {
    from_wintun: mpsc::Receiver<WintunPacket>,
    to_wintun: Option<std_mpsc::SyncSender<PooledBuffer>>,
    downlink_pool: BufferPool,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl WintunPump {
    fn start(
        adapter_name: &str,
        downlink_record_bytes: usize,
        write_drops: Option<crate::transport_core::udp_buffer::DropSink>,
    ) -> io::Result<Self> {
        let session = Arc::new(WintunSession::open(adapter_name)?);
        let (from_wintun_tx, mut from_wintun) = mpsc::channel(FROM_WINTUN_CAPACITY);
        let (to_wintun, to_wintun_rx) = std_mpsc::sync_channel(TO_WINTUN_CAPACITY);
        // Reserve one WIRE RECORD per slot, not one theoretical maximum packet: the caller
        // derives the bound from the negotiated MTU plus padding/normalisation headroom. This
        // is a reservation, not a cap — an outsized record still fits, it just grows its
        // buffer once.
        let downlink_slot = downlink_record_bytes.clamp(MIN_DOWNLINK_SLOT_BYTES, MAX_PACKET_BYTES);
        let downlink_capacity =
            (DOWNLINK_POOL_BYTES / downlink_slot).clamp(MIN_DOWNLINK_BUFFERS, MAX_DOWNLINK_BUFFERS);
        let downlink_pool = BufferPool::new(downlink_capacity, downlink_slot)?;
        let stop = Arc::new(AtomicBool::new(false));

        let reader_session = session.clone();
        let reader_stop = stop.clone();
        let reader = std::thread::Builder::new()
            .name("qeli-wintun-reader".into())
            .spawn(move || reader_loop(reader_session, from_wintun_tx, reader_stop))?;

        let writer_session = session;
        let writer_stop = stop.clone();
        let writer = match std::thread::Builder::new()
            .name("qeli-wintun-writer".into())
            .spawn(move || writer_loop(writer_session, to_wintun_rx, writer_stop, write_drops))
        {
            Ok(writer) => writer,
            Err(error) => {
                stop.store(true, Ordering::Release);
                from_wintun.close();
                drop(to_wintun);
                let _ = reader.join();
                return Err(error);
            }
        };

        Ok(Self {
            from_wintun,
            to_wintun: Some(to_wintun),
            downlink_pool,
            stop,
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    fn sender_to_tun(&self) -> TunWriter {
        TunWriter::from_parts(
            self.to_wintun
                .as_ref()
                .expect("Wintun sender is unavailable after shutdown")
                .clone(),
            self.downlink_pool.clone(),
        )
    }

    async fn recv_from_tun(&mut self) -> Option<WintunPacket> {
        self.from_wintun.recv().await
    }

    async fn shutdown(mut self) {
        self.request_stop();
        let reader = self.reader.take();
        let writer = self.writer.take();
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
            log::warn!("Wintun worker join failed: {error}");
        }
    }

    fn request_stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.from_wintun.close();
        self.to_wintun.take();
    }
}

impl Drop for WintunPump {
    fn drop(&mut self) {
        self.request_stop();
        // Cancellation/error paths skip async shutdown, but returning from qeli_client_run is
        // an ownership boundary: the next generation must not overlap this Wintun session.
        // Both loops use bounded waits (250 ms reader, 100 ms writer), so joining here cannot
        // park indefinitely and mirrors LinuxTunPump's cancellation-safe Drop contract.
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

fn reader_loop(
    session: Arc<WintunSession>,
    from_wintun: mpsc::Sender<WintunPacket>,
    stop: Arc<AtomicBool>,
) {
    log::info!("Wintun reader started");
    while !stop.load(Ordering::Acquire) {
        let mut packet_size = 0u32;
        let packet = session.receive(&mut packet_size);
        if !packet.is_null() {
            if packet_size == 0 || packet_size as usize > MAX_PACKET_BYTES {
                session.release(packet);
                log::warn!("Wintun returned invalid packet size {packet_size}");
                if packet_size as usize > MAX_PACKET_BYTES {
                    break;
                }
                continue;
            }
            let packet = WintunPacket {
                pointer: packet as usize,
                length: packet_size as usize,
                session: session.clone(),
            };
            if from_wintun.blocking_send(packet).is_err() {
                break;
            }
            continue;
        }

        match unsafe { GetLastError() } {
            ERROR_NO_MORE_ITEMS => {
                let waited =
                    unsafe { WaitForSingleObject(session.read_event as *mut c_void, READ_WAIT_MS) };
                if waited == WAIT_FAILED {
                    log::warn!("Wintun read-event wait failed: {}", unsafe {
                        GetLastError()
                    });
                    break;
                }
                if waited != WAIT_OBJECT_0 && waited != WAIT_TIMEOUT {
                    log::warn!("Wintun read-event wait returned unexpected status {waited}");
                    break;
                }
            }
            ERROR_HANDLE_EOF => break,
            ERROR_INVALID_DATA => {
                log::error!("Wintun receive ring is corrupt");
                break;
            }
            error => {
                log::warn!("WintunReceivePacket failed (Windows error {error})");
                break;
            }
        }
    }
    log::info!("Wintun reader stopped");
}

fn writer_loop(
    session: Arc<WintunSession>,
    to_wintun: std_mpsc::Receiver<PooledBuffer>,
    stop: Arc<AtomicBool>,
    write_drops: Option<crate::transport_core::udp_buffer::DropSink>,
) {
    log::info!("Wintun writer started");
    while !stop.load(Ordering::Acquire) {
        let packet = match to_wintun.recv_timeout(WRITER_STOP_POLL) {
            Ok(packet) => packet,
            Err(std_mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if packet.is_empty() {
            continue;
        }
        if packet.len() > MAX_PACKET_BYTES {
            if let Some(drops) = write_drops.as_ref() {
                drops.note();
            }
            continue;
        }
        let target = unsafe {
            (session.api.allocate_send_packet)(session.session as *mut c_void, packet.len() as u32)
        };
        if target.is_null() {
            match unsafe { GetLastError() } {
                ERROR_BUFFER_OVERFLOW => {
                    log::debug!("Wintun send ring is full; dropping one packet");
                    if let Some(drops) = write_drops.as_ref() {
                        drops.note();
                    }
                    continue;
                }
                ERROR_HANDLE_EOF => break,
                error => {
                    log::warn!("WintunAllocateSendPacket failed (Windows error {error}); stopping");
                    break;
                }
            }
        }
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), target, packet.len());
            (session.api.send_packet)(session.session as *mut c_void, target);
        }
    }
    log::info!("Wintun writer stopped");
}

pub(crate) enum TunPacket {
    Ring(WintunPacket),
    Packet(PooledBuffer),
}

impl Deref for TunPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Ring(packet) => packet,
            Self::Packet(packet) => packet,
        }
    }
}

impl AsRef<[u8]> for TunPacket {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

pub(crate) enum WindowsTunPump {
    Ring(WintunPump),
    Packet(PacketTunPump),
}

impl WindowsTunPump {
    pub(crate) fn open(
        adapter_name: &str,
        downlink_record_bytes: usize,
        write_drops: Option<crate::transport_core::udp_buffer::DropSink>,
    ) -> io::Result<Self> {
        WintunPump::start(adapter_name, downlink_record_bytes, write_drops).map(Self::Ring)
    }

    pub(crate) fn packet(pump: PacketTunPump) -> Self {
        Self::Packet(pump)
    }

    pub(crate) fn sender_to_tun(&self) -> TunWriter {
        match self {
            Self::Ring(pump) => pump.sender_to_tun(),
            Self::Packet(pump) => pump.sender_to_tun(),
        }
    }

    pub(crate) async fn recv_from_tun(&mut self) -> Option<TunPacket> {
        match self {
            Self::Ring(pump) => pump.recv_from_tun().await.map(TunPacket::Ring),
            Self::Packet(pump) => pump.recv_from_tun().await.map(TunPacket::Packet),
        }
    }

    pub(crate) async fn shutdown(self) {
        match self {
            Self::Ring(pump) => pump.shutdown().await,
            Self::Packet(pump) => pump.shutdown().await,
        }
    }
}
