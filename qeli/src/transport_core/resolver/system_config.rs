//! Bounded, descriptor-consistent resolver files. Symlinks are ordinary resolv.conf
//! deployment; file names alone never establish contents or a systemd stub.
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    path::Path,
};

pub(crate) const BYTE_LIMIT: u64 = 64 * 1024;
const ADDRESS_LIMIT: usize = 64;

pub(crate) fn read(path: &Path) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let before = file.metadata()?;
    read_opened(file, before)
}

fn read_opened(mut file: File, before: Metadata) -> io::Result<String> {
    if !before.is_file() || before.len() > BYTE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resolver configuration must be a regular file of at most 64 KiB",
        ));
    }
    let mut contents = String::new();
    file.by_ref()
        .take(BYTE_LIMIT + 1)
        .read_to_string(&mut contents)?;
    let after = file.metadata()?;
    if contents.len() as u64 > BYTE_LIMIT
        || contents.len() as u64 != after.len()
        || crate::config_source::Stamp::of(&before) != crate::config_source::Stamp::of(&after)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resolver configuration changed while reading",
        ));
    }
    Ok(contents)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Nameserver {
    pub(crate) address: IpAddr,
    // A scope must never be erased to create an unrestricted firewall allowance.
    pub(crate) scoped: bool,
}

fn nameserver(value: &str) -> Option<Nameserver> {
    if let Some((address, scope)) = value.split_once('%') {
        if scope.is_empty() || scope.contains('%') {
            return None;
        }
        return address
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|v6| Nameserver {
                address: IpAddr::V6(v6),
                scoped: true,
            });
    }
    value.parse().ok().map(|address| Nameserver {
        address,
        scoped: false,
    })
}

pub(crate) fn nameservers(contents: &str) -> io::Result<Vec<Nameserver>> {
    if contents.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NUL in resolver configuration",
        ));
    }
    let mut addresses = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let address = fields.next().and_then(nameserver);
        let Some(address) = address.filter(|_| {
            fields
                .next()
                .is_none_or(|rest| rest.starts_with(['#', ';']))
        }) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed nameserver directive",
            ));
        };
        if !addresses.contains(&address) {
            if addresses.len() == ADDRESS_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many resolver addresses",
                ));
            }
            addresses.push(address);
        }
    }
    Ok(addresses)
}

pub(super) fn snapshot(paths: &[&Path]) -> io::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    for path in paths {
        let parsed = match read(path).and_then(|text| nameservers(&text)) {
            Ok(parsed) => parsed,
            Err(_) => continue, // Unreadable/invalid files never grant port-53 allowances.
        };
        for entry in parsed {
            // Existing address-only rules cannot represent a scoped resolver. Keep
            // other valid entries, but do not broaden this one to every interface.
            if entry.scoped {
                continue;
            }
            let address = SocketAddr::new(entry.address, 53);
            if !addresses.contains(&address) {
                if addresses.len() == ADDRESS_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "too many system resolver addresses",
                    ));
                }
                addresses.push(address);
            }
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests;
