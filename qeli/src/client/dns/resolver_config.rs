//! A filename or a commented stub address cannot prove the system DNS path.
use crate::transport_core::resolver::system_config;
use std::path::Path;
#[cfg(test)]
const LIMIT: u64 = system_config::BYTE_LIMIT;

pub(super) fn uses_stub(path: &Path) -> bool {
    system_config::read(path)
        .map(|text| stub_only(&text))
        .unwrap_or(false)
}
fn stub_only(contents: &str) -> bool {
    system_config::nameservers(contents).is_ok_and(|addresses| {
        !addresses.is_empty() && addresses.iter().all(|address| {
            !address.scoped && matches!(address.address, std::net::IpAddr::V4(v4) if v4 == std::net::Ipv4Addr::new(127, 0, 0, 53) || v4 == std::net::Ipv4Addr::new(127, 0, 0, 54))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolver_config_requires_actual_stub_nameservers_only() {
        for value in [
            "nameserver 127.0.0.53\n",
            "  nameserver\t127.0.0.54 # proxy\nsearch example.test\n",
            "nameserver 127.0.0.53\nnameserver 127.0.0.54\n",
        ] {
            assert!(stub_only(value), "{value:?}");
        }
        for value in [
            "",
            "# nameserver 127.0.0.53\nnameserver 192.0.2.53",
            "search 127.0.0.53",
            "nameserver 127.0.0.530",
            "nameserver 127.0.0.53\nnameserver 192.0.2.53",
            "nameserver 127.0.0.53 extra",
            "nameserver 127.0.0.53#attached",
            "nameserver 127.0.0.53\nnameserver fe80::53%wan0",
            "nameserver 127.0.0.53\nnameserver 2001:db8::53%2",
            "nameserver\n",
            "nameserver 127.0.0.53\0\nnameserver 192.0.2.53",
        ] {
            assert!(!stub_only(value), "{value:?}");
        }
    }
    #[test]
    fn resolver_config_symlink_name_never_bypasses_content_check() {
        use std::os::unix::fs::symlink;
        let tmp = super::super::tests::Tmp::new("resolver-config");
        let target = tmp.path("stub-resolv.conf");
        let link = tmp.path("resolv.conf");
        symlink(&target, &link).unwrap();
        assert!(!uses_stub(&link), "dangling link");
        std::fs::write(&target, "nameserver 192.0.2.53\n").unwrap();
        assert!(!uses_stub(&link), "stub-like name with real upstream");
        std::fs::write(&target, "nameserver 127.0.0.53\n").unwrap();
        assert!(uses_stub(&link));
        std::fs::write(&target, vec![b'#'; LIMIT as usize + 1]).unwrap();
        assert!(!uses_stub(&link));
        std::fs::write(&target, [0xff]).unwrap();
        assert!(!uses_stub(&link));
    }
    #[test]
    fn resolver_config_fifo_is_refused_without_waiting_for_writer() {
        use std::{
            ffi::CString,
            os::unix::ffi::OsStrExt,
            time::{Duration, Instant},
        };
        let tmp = super::super::tests::Tmp::new("resolver-fifo");
        let path = tmp.path("fifo");
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is NUL-terminated and lives through this syscall.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        assert!(!uses_stub(&path));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
