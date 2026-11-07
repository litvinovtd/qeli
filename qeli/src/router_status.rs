//! Verify the real namespace, link generation and assigned addresses for router status.
use serde_json::Value;
use std::{collections::HashSet, net::IpAddr};

pub(crate) fn ready(device: &str, index: u32, expected: &[IpAddr]) -> bool {
    if expected.is_empty() || expected.len() > 2 {
        return false;
    }
    let Ok(Some((seen, flags))) = crate::network_interface::state(device) else {
        return false;
    };
    if seen != index || flags & 1 == 0 {
        return false;
    }
    let mut head = std::ptr::null_mut();
    // SAFETY: libc initializes one owned linked list, released once below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return false;
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _owned = Addresses(head);
    let mut found = HashSet::new();
    let mut at = head;
    while !at.is_null() {
        // SAFETY: getifaddrs owns every list node and the sockaddr of its family.
        let item = unsafe { &*at };
        at = item.ifa_next;
        if item.ifa_name.is_null() || item.ifa_addr.is_null() {
            continue;
        }
        if unsafe { std::ffi::CStr::from_ptr(item.ifa_name) }.to_bytes() != device.as_bytes() {
            continue;
        }
        match unsafe { (*item.ifa_addr).sa_family as i32 } {
            libc::AF_INET => {
                let address = unsafe { &*(item.ifa_addr as *const libc::sockaddr_in) };
                found.insert(IpAddr::V4(std::net::Ipv4Addr::from(
                    address.sin_addr.s_addr.to_ne_bytes(),
                )));
            }
            libc::AF_INET6 => {
                let address = unsafe { &*(item.ifa_addr as *const libc::sockaddr_in6) };
                found.insert(IpAddr::V6(std::net::Ipv6Addr::from(
                    address.sin6_addr.s6_addr,
                )));
            }
            _ => {}
        }
    }
    expected.iter().all(|a| found.contains(a))
        && crate::network_interface::state(device).ok().flatten() == Some((index, flags))
}
pub(crate) fn project(body: &mut Value) {
    if body["tunnel"]["state"] != "connected" {
        return;
    }
    let ready = (|| {
        let device = body["tunnel"]["device"].as_str()?;
        let index = u32::try_from(body["tunnel"]["ifindex"].as_u64()?).ok()?;
        let expected = body["tunnel"]["addresses"]
            .as_array()?
            .iter()
            .map(|v| v.as_str()?.parse::<IpAddr>().ok())
            .collect::<Option<Vec<_>>>()?;
        Some(self::ready(device, index, &expected))
    })()
    .unwrap_or(false);
    if !ready {
        body["tunnel"]["state"] = Value::String("connecting".into());
        body["tunnel"]["last_error_code"] = Value::String("network_not_ready".into());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_or_unassigned_plan_is_never_ready() {
        assert!(!ready("lo", 1, &[]));
        assert!(!ready("lo", 1, &["192.0.2.193".parse().unwrap()]));
        let mut value = serde_json::json!({"tunnel":{"state":"connected","device":"qeli-missing","ifindex":1,"addresses":["192.0.2.1"]}});
        project(&mut value);
        assert_eq!(value["tunnel"]["state"], "connecting");
        assert_eq!(value["tunnel"]["last_error_code"], "network_not_ready");
    }
}
