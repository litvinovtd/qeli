use super::*;
struct Tmp(std::path::PathBuf);
impl Tmp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qeli-resolver-config-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exact_nameserver_tokens_comments_and_order_are_preserved() {
    let text = "# ignored\nsearch example.test\nnameserver192.0.2.99\n  nameserver\t192.0.2.53 # first\r\nnameserver 2001:db8::53 ; second\nnameserver 192.0.2.53\n";
    assert_eq!(
        nameservers(text)
            .unwrap()
            .into_iter()
            .map(|entry| entry.address)
            .collect::<Vec<_>>(),
        vec![
            "192.0.2.53".parse::<IpAddr>().unwrap(),
            "2001:db8::53".parse().unwrap()
        ]
    );
    assert!(nameservers("nameserver192.0.2.99").unwrap().is_empty());
}

#[test]
fn malformed_directive_never_returns_a_partial_allowlist() {
    for bad in [
        "nameserver",
        "nameserver invalid",
        "nameserver 192.0.2.1 extra",
        "nameserver 192.0.2.1\0",
        "nameserver [::1]",
        "nameserver 192.0.2.1#attached",
        "nameserver 2001:db8::53;attached",
        "nameserver fe80::53%",
        "nameserver fe80::53%wan0%2",
        "nameserver 192.0.2.53%wan0",
    ] {
        assert!(
            nameservers(&format!("nameserver 192.0.2.53\n{bad}")).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn distinct_address_budget_does_not_count_duplicates() {
    assert_eq!(
        nameservers(&"nameserver 192.0.2.53\n".repeat(100))
            .unwrap()
            .len(),
        1
    );
    let text = (1..=ADDRESS_LIMIT)
        .map(|i| format!("nameserver 192.0.2.{i}\n"))
        .collect::<String>();
    assert_eq!(nameservers(&text).unwrap().len(), ADDRESS_LIMIT);
    assert!(nameservers(&(text + "nameserver 192.0.2.200\n")).is_err());
}

#[test]
fn file_limits_and_invalid_input_are_rejected_before_parsing() {
    let tmp = Tmp::new();
    let path = tmp.path("resolv.conf");
    assert!(read(&path).is_err());
    assert!(read(&tmp.0).is_err());
    std::fs::write(&path, vec![b'#'; BYTE_LIMIT as usize]).unwrap();
    assert_eq!(read(&path).unwrap().len(), BYTE_LIMIT as usize);
    std::fs::write(&path, vec![b'#'; BYTE_LIMIT as usize + 1]).unwrap();
    assert!(read(&path).is_err());
    std::fs::write(&path, [0xff]).unwrap();
    assert!(read(&path).is_err());
}

#[test]
fn changed_opened_inode_does_not_publish_mixed_contents() {
    let tmp = Tmp::new();
    let path = tmp.path("resolv.conf");
    std::fs::write(&path, "nameserver 192.0.2.53\n").unwrap();
    let file = File::open(&path).unwrap();
    let before = file.metadata().unwrap();
    std::fs::write(&path, "nameserver 2001:db8::53\n").unwrap();
    assert!(read_opened(file, before).is_err());
}

#[test]
fn snapshot_ignores_invalid_files_but_never_the_combined_budget() {
    let tmp = Tmp::new();
    let first = tmp.path("first");
    let second = tmp.path("second");
    std::fs::write(&first, "nameserver 192.0.2.54\nnameserver broken\n").unwrap();
    std::fs::write(&second, "nameserver 192.0.2.53\n").unwrap();
    assert_eq!(
        snapshot(&[&first, &tmp.path("missing"), &second]).unwrap(),
        vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap()]
    );
    let text = (1..=ADDRESS_LIMIT)
        .map(|i| format!("nameserver 198.51.100.{i}\n"))
        .collect::<String>();
    std::fs::write(&first, text).unwrap();
    assert!(snapshot(&[&first, &second]).is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_follow_opened_contents_not_their_names() {
    let tmp = Tmp::new();
    let target = tmp.path("stub-resolv.conf");
    let path = tmp.path("resolv.conf");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(read(&path).is_err());
    std::fs::write(&target, "nameserver 192.0.2.53\n").unwrap();
    assert_eq!(read(&path).unwrap(), "nameserver 192.0.2.53\n");
}

#[cfg(unix)]
#[test]
fn fifo_is_refused_without_waiting_for_a_writer() {
    use std::{
        ffi::CString,
        os::unix::ffi::OsStrExt,
        time::{Duration, Instant},
    };
    let tmp = Tmp::new();
    let path = tmp.path("fifo");
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let started = Instant::now();
    assert!(read(&path).is_err());
    assert!(snapshot(&[&path]).unwrap().is_empty());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn scoped_entries_preserve_other_resolvers_without_losing_their_scope() {
    let tmp = Tmp::new();
    let path = tmp.path("resolv.conf");
    let text = "nameserver 192.0.2.53\nnameserver fe80::53%wan0\nnameserver fe80::54%2\nnameserver 2001:db8::53%wan0\n";
    let entries = nameservers(text).unwrap();
    assert_eq!(entries.len(), 4);
    assert!(!entries[0].scoped);
    assert!(entries[1..].iter().all(|entry| entry.scoped));
    std::fs::write(&path, text).unwrap();
    assert_eq!(
        snapshot(&[&path]).unwrap(),
        vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap()]
    );
}
