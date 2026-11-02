//! Per-socket receive requests. Linux auto clients can bypass an undersized host limit,
//! but all their live controllers share a memory budget; fixed/zero/server policy is unchanged.
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

// Do not issue repeated FORCE requests for tiny MemAvailable fluctuations.
const CLIENT_RESERVATION_STEP: u32 = 256 * 1024;

trait ReceiveSocket {
    fn receive_bytes(&self) -> io::Result<u32>;
    fn standard_limit(&self) -> Option<u32>;
    fn set_receive(&self, bytes: u32) -> io::Result<()>;
    fn force_receive(&self, bytes: u32) -> io::Result<()>;
}

impl ReceiveSocket for socket2::SockRef<'_> {
    fn receive_bytes(&self) -> io::Result<u32> {
        self.recv_buffer_size()
            .map(|raw| super::normalize_os_bytes(raw).min(u32::MAX as usize) as u32)
    }
    fn standard_limit(&self) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/sys/net/core/rmem_max")
                .ok()?
                .trim()
                .parse()
                .ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
    fn set_receive(&self, bytes: u32) -> io::Result<()> {
        self.set_recv_buffer_size(bytes as usize)
    }
    fn force_receive(&self, bytes: u32) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let value = libc::c_int::try_from(bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "UDP buffer exceeds c_int")
            })?;
            // SAFETY: value is a live c_int, its exact size is passed, and SockRef keeps the FD alive.
            let result = unsafe {
                libc::setsockopt(
                    self.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUFFORCE,
                    (&value as *const libc::c_int).cast(),
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = bytes;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux UDP FORCE is unavailable",
            ))
        }
    }
}

#[derive(Default)]
struct ClientMemoryBudget {
    reserved_kernel_bytes: u64,
}

fn process_budget() -> Arc<Mutex<ClientMemoryBudget>> {
    static BUDGET: OnceLock<Arc<Mutex<ClientMemoryBudget>>> = OnceLock::new();
    BUDGET
        .get_or_init(|| Arc::new(Mutex::new(ClientMemoryBudget::default())))
        .clone()
}

fn available_memory_bytes() -> Option<u64> {
    if let Some(bytes) = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| parse_available_memory(&text))
    {
        return Some(bytes);
    }
    // Older router kernels may expose MemFree but not MemAvailable. Free physical
    // pages are a conservative fallback; an unknown observation grants no increase.
    #[cfg(target_os = "linux")]
    unsafe {
        let pages = libc::sysconf(libc::_SC_AVPHYS_PAGES);
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        if pages > 0 && page_size > 0 {
            return (pages as u64).checked_mul(page_size as u64);
        }
    }
    None
}

fn parse_available_memory(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "MemAvailable:" {
            return None;
        }
        let kib = fields.next()?.parse::<u64>().ok()?;
        if fields.next()? != "kB" {
            return None;
        }
        kib.checked_mul(1024)
    })
}

struct ClientReservation {
    budget: Arc<Mutex<ClientMemoryBudget>>,
    reserved: u64,
    send_kernel_bytes: u64,
}

impl ClientReservation {
    fn new(budget: Arc<Mutex<ClientMemoryBudget>>, receive: u32, send_kernel_bytes: u64) -> Self {
        let reserved = u64::from(receive)
            .saturating_mul(2)
            .saturating_add(send_kernel_bytes);
        budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reserved_kernel_bytes += reserved;
        Self {
            budget,
            reserved,
            send_kernel_bytes,
        }
    }

    /// Reserve before setsockopt. Existing queues never shrink under memory pressure.
    /// Unknown memory authorizes no increase. Linux's raw receive accounting is twice the request.
    fn reserve_growth(&mut self, desired: u32, available: Option<u64>) -> Option<u32> {
        let available = available?;
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let others = budget.reserved_kernel_bytes.saturating_sub(self.reserved);
        let receive_allowance = (available / 8)
            .saturating_sub(others)
            .saturating_sub(self.send_kernel_bytes)
            / 2;
        let target = u64::from(desired)
            .min(receive_allowance)
            .min(u64::from(u32::MAX)) as u32;
        let target = target / CLIENT_RESERVATION_STEP * CLIENT_RESERVATION_STEP;
        let next = u64::from(target) * 2 + self.send_kernel_bytes;
        if next <= self.reserved {
            return None;
        }
        budget.reserved_kernel_bytes = others.saturating_add(next);
        self.reserved = next;
        Some(target)
    }

    fn reconcile(&mut self, receive: Option<u32>) {
        // A failed readback must retain the conservative reservation, not invent a smaller grant.
        let Some(receive) = receive else {
            return;
        };
        let actual = u64::from(receive) * 2 + self.send_kernel_bytes;
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        budget.reserved_kernel_bytes = budget
            .reserved_kernel_bytes
            .saturating_sub(self.reserved)
            .saturating_add(actual);
        self.reserved = actual;
    }
}

impl Drop for ClientReservation {
    fn drop(&mut self) {
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        budget.reserved_kernel_bytes = budget.reserved_kernel_bytes.saturating_sub(self.reserved);
    }
}

pub(super) struct ReceiveBufferRequest {
    automatic: bool,
    forced: bool,
    force_blocked: bool,
    force_error: Option<i32>,
    budget_limited: bool,
    os_default: bool,
    reservation: Option<ClientReservation>,
}

impl ReceiveBufferRequest {
    pub(super) fn new(socket: &socket2::SockRef<'_>, client: bool, automatic: bool) -> Self {
        let reservation = if cfg!(target_os = "linux") && client && automatic {
            // Missing readback does not authorize bypassing a host memory limit.
            socket
                .receive_bytes()
                .ok()
                .zip(socket.send_buffer_size().ok())
                .map(|(receive, send)| {
                    ClientReservation::new(process_budget(), receive, send as u64)
                })
        } else {
            None
        };
        Self {
            automatic,
            forced: false,
            force_blocked: false,
            force_error: None,
            budget_limited: false,
            os_default: false,
            reservation,
        }
    }

    pub(super) fn method(&self) -> &'static str {
        if self.os_default {
            "os-default"
        } else if self.forced {
            "force"
        } else {
            "standard"
        }
    }
    pub(super) fn force_error(&self) -> Option<i32> {
        self.force_error
    }
    pub(super) fn budget_limited(&self) -> bool {
        self.budget_limited
    }

    pub(super) fn request(
        &mut self,
        socket: &socket2::SockRef<'_>,
        desired: u32,
        label: &str,
    ) -> Option<u32> {
        let available = self
            .reservation
            .as_ref()
            .and_then(|_| available_memory_bytes());
        self.request_with_memory(socket, desired, label, available)
    }

    fn request_with_memory<S: ReceiveSocket>(
        &mut self,
        socket: &S,
        desired: u32,
        label: &str,
        available: Option<u64>,
    ) -> Option<u32> {
        let desired = if self.automatic {
            desired.min(super::AUTO_MAX_RECV_BYTES)
        } else {
            desired
        };
        self.os_default = desired == 0;
        if desired == 0 {
            return None;
        }
        let before = socket.receive_bytes().ok();
        if self.automatic && before.is_some_and(|bytes| bytes >= desired) {
            // Advance the controller's rung even if the socket already has this much memory.
            return Some(desired);
        }
        // Once FORCE succeeded, a standard request could shrink the queue to rmem_max.
        // A later capability loss must leave the working queue intact.
        if self.forced && self.force_blocked {
            return Some(desired);
        }
        let target = if let Some(reservation) = self.reservation.as_mut() {
            match reservation.reserve_growth(desired, available) {
                Some(target) => {
                    self.budget_limited = target < desired;
                    target
                }
                None => {
                    self.budget_limited = true;
                    return None;
                }
            }
        } else {
            desired
        };

        let standard_would_shrink = self.automatic
            && before
                .zip(socket.standard_limit())
                .is_some_and(|(current, limit)| current > limit);
        if self.forced || standard_would_shrink {
            if self.reservation.is_some() && !self.force_blocked {
                self.try_force(socket, target, label);
            }
        } else {
            if let Err(error) = socket.set_receive(target) {
                log::warn!("{label}: could not request UDP SO_RCVBUF={target}: {error}; using kernel value");
            }
            let granted = socket.receive_bytes().ok();
            if self.reservation.is_some()
                && !self.force_blocked
                && granted.is_some_and(|bytes| bytes < target)
            {
                self.try_force(socket, target, label);
            }
        }
        if let Some(reservation) = self.reservation.as_mut() {
            reservation.reconcile(socket.receive_bytes().ok());
        }
        Some(target)
    }

    fn try_force<S: ReceiveSocket>(&mut self, socket: &S, target: u32, label: &str) {
        match socket.force_receive(target) {
            Ok(()) => {
                self.forced = true;
                self.force_error = None;
                log::info!("{label}: requested UDP SO_RCVBUFFORCE={target}; global socket limits unchanged, verifying readback");
            }
            Err(error) => {
                self.force_error = error.raw_os_error();
                self.force_blocked = error.kind() == io::ErrorKind::PermissionDenied
                    || error.kind() == io::ErrorKind::Unsupported;
                #[cfg(target_os = "linux")]
                {
                    self.force_blocked |= matches!(
                        error.raw_os_error(),
                        Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP)
                    );
                }
                log::warn!("{label}: UDP SO_RCVBUFFORCE={target} failed: {error}; retaining the actual kernel buffer");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    const MIB: u32 = 1024 * 1024;

    struct Socket {
        received: Cell<u32>,
        limit: u32,
        force_denied: Cell<bool>,
        read_failed: Cell<bool>,
        calls: RefCell<Vec<(&'static str, u32)>>,
    }
    impl Socket {
        fn new() -> Self {
            Self {
                received: Cell::new(106496),
                limit: 212992,
                force_denied: Cell::new(false),
                read_failed: Cell::new(false),
                calls: RefCell::new(vec![]),
            }
        }
    }
    impl ReceiveSocket for Socket {
        fn receive_bytes(&self) -> io::Result<u32> {
            if self.read_failed.get() {
                Err(io::ErrorKind::Other.into())
            } else {
                Ok(self.received.get())
            }
        }
        fn standard_limit(&self) -> Option<u32> {
            Some(self.limit)
        }
        fn set_receive(&self, bytes: u32) -> io::Result<()> {
            self.calls.borrow_mut().push(("standard", bytes));
            self.received.set(bytes.min(self.limit));
            Ok(())
        }
        fn force_receive(&self, bytes: u32) -> io::Result<()> {
            self.calls.borrow_mut().push(("force", bytes));
            if self.force_denied.get() {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.received.set(bytes);
            Ok(())
        }
    }
    fn request(socket: &Socket, budget: Arc<Mutex<ClientMemoryBudget>>) -> ReceiveBufferRequest {
        ReceiveBufferRequest {
            automatic: true,
            forced: false,
            force_blocked: false,
            force_error: None,
            budget_limited: false,
            os_default: false,
            reservation: Some(ClientReservation::new(
                budget,
                socket.received.get(),
                212992,
            )),
        }
    }
    fn memory() -> Option<u64> {
        Some(512 * u64::from(MIB))
    }

    #[test]
    fn force_bypasses_clamp_and_growth_never_uses_standard_again() {
        let socket = Socket::new();
        let mut setter = request(&socket, Default::default());
        setter.request_with_memory(&socket, 4 * MIB, "test", memory());
        assert_eq!(socket.received.get(), 4 * MIB);
        setter.request_with_memory(&socket, 8 * MIB, "test", memory());
        assert_eq!(socket.received.get(), 8 * MIB);
        assert_eq!(
            *socket.calls.borrow(),
            vec![
                ("standard", 4 * MIB),
                ("force", 4 * MIB),
                ("force", 8 * MIB)
            ]
        );
    }
    #[test]
    fn later_permission_loss_preserves_forced_buffer_and_does_not_retry() {
        let socket = Socket::new();
        let mut setter = request(&socket, Default::default());
        setter.request_with_memory(&socket, 4 * MIB, "test", memory());
        socket.force_denied.set(true);
        setter.request_with_memory(&socket, 8 * MIB, "test", memory());
        setter.request_with_memory(&socket, 16 * MIB, "test", memory());
        assert_eq!(socket.received.get(), 4 * MIB);
        assert_eq!(socket.calls.borrow().len(), 3);
    }
    #[test]
    fn initial_permission_denial_is_only_attempted_once() {
        let socket = Socket::new();
        socket.force_denied.set(true);
        let mut setter = request(&socket, Default::default());
        for bytes in [4 * MIB, 8 * MIB, 16 * MIB] {
            setter.request_with_memory(&socket, bytes, "test", memory());
        }
        assert_eq!(socket.received.get(), socket.limit);
        assert_eq!(
            socket
                .calls
                .borrow()
                .iter()
                .filter(|(kind, _)| *kind == "force")
                .count(),
            1
        );
    }
    #[test]
    fn zero_and_explicit_fixed_keep_their_original_semantics() {
        let socket = Socket::new();
        let mut setter = ReceiveBufferRequest {
            automatic: false,
            forced: false,
            force_blocked: false,
            force_error: None,
            budget_limited: false,
            os_default: false,
            reservation: None,
        };
        setter.request_with_memory(&socket, 0, "test", memory());
        assert!(socket.calls.borrow().is_empty());
        assert_eq!(setter.method(), "os-default");
        setter.request_with_memory(&socket, 4 * MIB, "test", memory());
        setter.request_with_memory(&socket, 16384, "test", memory());
        assert_eq!(socket.received.get(), 16384);
        assert_eq!(
            *socket.calls.borrow(),
            vec![("standard", 4 * MIB), ("standard", 16384)]
        );
    }
    #[test]
    fn unknown_readback_does_not_authorize_force_or_release_reserved_memory() {
        let socket = Socket::new();
        let budget = Arc::default();
        let mut setter = request(&socket, Arc::clone(&budget));
        socket.read_failed.set(true);
        setter.request_with_memory(&socket, 4 * MIB, "test", memory());
        assert_eq!(*socket.calls.borrow(), vec![("standard", 4 * MIB)]);
        assert!(budget.lock().unwrap().reserved_kernel_bytes >= u64::from(8 * MIB));
    }
    #[test]
    fn unknown_or_low_memory_does_not_allocate_or_shrink_a_working_socket() {
        let socket = Socket::new();
        let mut setter = request(&socket, Default::default());
        assert_eq!(
            setter.request_with_memory(&socket, 4 * MIB, "test", None),
            None
        );
        setter.request_with_memory(&socket, 4 * MIB, "test", memory());
        assert_eq!(
            setter.request_with_memory(&socket, 8 * MIB, "test", Some(1024)),
            None
        );
        assert_eq!(socket.received.get(), 4 * MIB);
    }
    #[test]
    fn overlapping_paths_share_budget_and_release_it_after_drain() {
        let budget = Arc::default();
        let one = Socket::new();
        let two = Socket::new();
        let available = Some(128 * u64::from(MIB));
        let mut active = request(&one, Arc::clone(&budget));
        active.request_with_memory(&one, 4 * MIB, "active", available);
        let mut candidate = request(&two, Arc::clone(&budget));
        candidate.request_with_memory(&two, 4 * MIB, "candidate", available);
        assert!(two.received.get() < 4 * MIB);
        assert!(budget.lock().unwrap().reserved_kernel_bytes <= available.unwrap() / 8);
        drop(active);
        candidate.request_with_memory(&two, 4 * MIB, "committed", available);
        assert_eq!(two.received.get(), 4 * MIB);
        drop(candidate);
        assert_eq!(budget.lock().unwrap().reserved_kernel_bytes, 0);
    }
    #[test]
    fn existing_large_buffer_advances_rungs_and_survives_a_lower_host_limit() {
        let socket = Socket::new();
        socket.received.set(8 * MIB);
        socket.force_denied.set(true);
        let mut setter = request(&socket, Default::default());
        assert_eq!(
            setter.request_with_memory(&socket, 4 * MIB, "test", memory()),
            Some(4 * MIB)
        );
        assert_eq!(
            setter.request_with_memory(&socket, 8 * MIB, "test", memory()),
            Some(8 * MIB)
        );
        setter.request_with_memory(&socket, 16 * MIB, "test", memory());
        assert_eq!(socket.received.get(), 8 * MIB);
        assert_eq!(*socket.calls.borrow(), vec![("force", 16 * MIB)]);
    }
    #[test]
    fn server_auto_does_not_bypass_a_limit_or_shrink_an_existing_buffer() {
        let socket = Socket::new();
        socket.received.set(4 * MIB);
        let mut setter = ReceiveBufferRequest {
            automatic: true,
            forced: false,
            force_blocked: false,
            force_error: None,
            budget_limited: false,
            os_default: false,
            reservation: None,
        };
        setter.request_with_memory(&socket, 8 * MIB, "test", memory());
        assert_eq!(socket.received.get(), 4 * MIB);
        assert!(socket.calls.borrow().is_empty());
    }
    #[test]
    fn automatic_force_cannot_exceed_the_hard_per_socket_cap() {
        let socket = Socket::new();
        let mut setter = request(&socket, Default::default());
        setter.request_with_memory(&socket, 64 * MIB, "test", memory());
        assert_eq!(socket.received.get(), super::super::AUTO_MAX_RECV_BYTES);
    }
    #[test]
    fn concurrent_reservations_cannot_overcommit_and_are_released() {
        let budget = Arc::new(Mutex::new(ClientMemoryBudget::default()));
        let ready = Arc::new(std::sync::Barrier::new(5));
        let grown = Arc::new(std::sync::Barrier::new(5));
        let release = Arc::new(std::sync::Barrier::new(5));
        let mut threads = vec![];
        for _ in 0..4 {
            let (budget, ready, grown, release) = (
                budget.clone(),
                ready.clone(),
                grown.clone(),
                release.clone(),
            );
            threads.push(std::thread::spawn(move || {
                let mut reservation = ClientReservation::new(budget, 65536, 65536);
                ready.wait();
                reservation.reserve_growth(4 * MIB, Some(128 * u64::from(MIB)));
                grown.wait();
                release.wait();
            }));
        }
        ready.wait();
        grown.wait();
        let peak_reserved = budget.lock().unwrap().reserved_kernel_bytes;
        release.wait();
        for t in threads {
            t.join().unwrap();
        }
        assert!(peak_reserved <= 16 * u64::from(MIB));
        assert_eq!(budget.lock().unwrap().reserved_kernel_bytes, 0);
    }
    #[test]
    fn tiny_memory_fluctuations_do_not_repeat_force_requests() {
        let socket = Socket::new();
        let mut setter = request(&socket, Default::default());
        setter.request_with_memory(&socket, 4 * MIB, "test", Some(32 * u64::from(MIB)));
        let before = socket.calls.borrow().len();
        assert!(socket.received.get() > socket.limit);
        setter.request_with_memory(&socket, 8 * MIB, "test", Some(32 * u64::from(MIB) + 4096));
        assert_eq!(socket.calls.borrow().len(), before);
    }
    #[test]
    fn memory_parser_is_checked_and_requires_available_memory() {
        assert_eq!(
            parse_available_memory("MemAvailable: 1024 kB\n"),
            Some(1048576)
        );
        assert_eq!(parse_available_memory("MemTotal: 999999 kB\n"), None);
        assert_eq!(parse_available_memory("MemAvailable: 1024 bytes\n"), None);
        assert_eq!(
            parse_available_memory("MemAvailable: 18446744073709551615 kB\n"),
            None
        );
    }
}
