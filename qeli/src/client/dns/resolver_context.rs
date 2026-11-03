//! Bind numeric per-link resolver commands to the system bus and service network.
//! This is an observation guard, not an atomic lock against a privileged service move.
use crate::system_command::Command;
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::{ffi::OsStringExt, fs::MetadataExt},
    path::PathBuf,
    time::{Duration, Instant},
};

const RESOLVED: &str = "org.freedesktop.resolve1";
const DEFAULT_BUS: &str = "unix:path=/run/dbus/system_bus_socket";

#[derive(Debug, PartialEq, Eq)]
struct Service {
    owner: String,
    pid: u32,
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    bus_id: String,
    resolved: Service,
}

pub(super) struct Context {
    address: String,
    network: File,
    snapshot: Snapshot,
}
impl Context {
    pub(super) fn capture(until: Instant) -> anyhow::Result<Self> {
        let address = match std::env::var("DBUS_SYSTEM_BUS_ADDRESS") {
            Ok(value) if !value.is_empty() => value,
            Ok(_) | Err(std::env::VarError::NotPresent) => DEFAULT_BUS.into(),
            Err(error) => return Err(error.into()),
        };
        Self::capture_at(address, until)
    }
    fn capture_at(address: String, until: Instant) -> anyhow::Result<Self> {
        remaining(until)?;
        let (_, _, guid) = bus_peer(&address, until)?;
        let address = pin_address(&address, &guid)?;
        let network = File::open("/proc/thread-self/ns/net")?;
        let snapshot = observe(&address, &network, until)?;
        Ok(Self {
            address,
            network,
            snapshot,
        })
    }
    #[cfg(test)]
    pub(super) fn address(&self) -> &str {
        &self.address
    }

    // Send mutations to the captured UNIQUE owner. A daemon restart cannot retarget
    // them, and neither activation nor resolvectl's networkd fallback is permitted.
    pub(super) fn apply(
        &self,
        operation: &str,
        index: &str,
        values: &[String],
        until: Instant,
    ) -> anyhow::Result<()> {
        let index = index
            .parse::<i32>()
            .ok()
            .filter(|i| *i > 0)
            .ok_or_else(|| anyhow::anyhow!("invalid resolver link index"))?;
        let (method, signature, payload) = payload(operation, index, values)?;
        remaining(until)?;
        let output = Command::new(busctl())
            .args([
                "--no-pager",
                "--auto-start=no",
                &format!("--address={}", self.address),
                "call",
                &self.snapshot.resolved.owner,
                "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager",
                method,
                signature,
            ])
            .args(&payload)
            .output_until(until)?;
        remaining(until)?;
        anyhow::ensure!(
            output.status.success(),
            "systemd-resolved {method} on link {index} failed: {}; DNS lease retained",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }
    pub(super) fn verify(&self, until: Instant) -> anyhow::Result<()> {
        let actual = observe(&self.address, &self.network, until)?;
        anyhow::ensure!(
            actual == self.snapshot,
            "DNS bus or service owner changed; retaining the DNS lease for recovery"
        );
        Ok(())
    }
}
fn remaining(until: Instant) -> io::Result<Duration> {
    until
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS resolver context deadline expired",
            )
        })
}
fn same_namespace(a: &File, b: &File) -> anyhow::Result<bool> {
    let a = a.metadata()?;
    let b = b.metadata()?;
    Ok((a.dev(), a.ino()) == (b.dev(), b.ino()))
}
fn endpoint(address: &str) -> anyhow::Result<PathBuf> {
    let fields = address
        .strip_prefix("unix:")
        .ok_or_else(|| anyhow::anyhow!("managed DNS requires a local Unix system bus"))?;
    let mut endpoint = None;
    let mut guid_seen = false;
    for field in fields.split(',') {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid system bus address"))?;
        if key == "guid" {
            anyhow::ensure!(
                !guid_seen && value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid system bus GUID"
            );
            guid_seen = true;
            continue;
        }
        anyhow::ensure!(
            endpoint.is_none() && matches!(key, "path" | "abstract"),
            "unsupported system bus address"
        );
        let mut decoded = Vec::new();
        let mut bytes = value.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let hi = bytes.next().and_then(|v| (v as char).to_digit(16));
                let lo = bytes.next().and_then(|v| (v as char).to_digit(16));
                decoded.push(
                    hi.zip(lo)
                        .map(|(a, b)| (a * 16 + b) as u8)
                        .ok_or_else(|| anyhow::anyhow!("invalid system bus escape"))?,
                );
            } else {
                anyhow::ensure!(
                    byte.is_ascii_alphanumeric() || b"_-/.\\".contains(&byte),
                    "invalid system bus address character"
                );
                decoded.push(byte);
            }
        }
        anyhow::ensure!(
            !decoded.is_empty() && !decoded.contains(&0),
            "empty or NUL system bus endpoint"
        );
        if key == "abstract" {
            decoded.insert(0, 0);
        } else {
            anyhow::ensure!(decoded[0] == b'/', "system bus path must be absolute");
        }
        endpoint = Some(PathBuf::from(std::ffi::OsString::from_vec(decoded)));
    }
    endpoint.ok_or_else(|| anyhow::anyhow!("system bus endpoint missing"))
}
fn pin_address(address: &str, guid: &str) -> anyhow::Result<String> {
    // GetId identifies the message bus; the AUTH GUID identifies the endpoint.
    // They are distinct in the D-Bus protocol. sd-bus checks the address GUID
    // during authentication, before it can send any method to a replacement bus.
    endpoint(address)?;
    if let Some(expected) = address.split(',').find_map(|f| f.strip_prefix("guid=")) {
        anyhow::ensure!(
            expected.eq_ignore_ascii_case(guid),
            "DNS bus authentication GUID changed"
        );
        Ok(address.to_string())
    } else {
        Ok(format!("{address},guid={guid}"))
    }
}
fn authentication_guid(socket: &socket2::Socket, until: Instant) -> anyhow::Result<String> {
    let mut stream = std::os::unix::net::UnixStream::from(socket.try_clone()?);
    stream.set_write_timeout(Some(remaining(until)?))?;
    // SAFETY: geteuid has no preconditions and does not modify process state.
    let identity = unsafe { libc::geteuid() }.to_string();
    let hex: String = identity.bytes().map(|b| format!("{b:02x}")).collect();
    stream.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
    let mut reply = Vec::new();
    // Bound both the response size and the total time, including a trickle peer.
    while reply.len() < 128 && !reply.ends_with(b"\r\n") {
        stream.set_read_timeout(Some(remaining(until)?))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        reply.push(byte[0]);
    }
    remaining(until)?;
    let guid = std::str::from_utf8(&reply)?
        .strip_prefix("OK ")
        .and_then(|s| s.strip_suffix("\r\n"))
        .filter(|s| {
            s.len() == 32
                && s.bytes().all(|b| b.is_ascii_hexdigit())
                && s.bytes().any(|b| b != b'0')
        })
        .ok_or_else(|| anyhow::anyhow!("invalid DNS bus authentication reply"))?;
    Ok(guid.to_ascii_lowercase())
}
fn bus_peer(
    address: &str,
    until: Instant,
) -> anyhow::Result<(socket2::Socket, libc::ucred, String)> {
    let duration = remaining(until)?;
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.connect_timeout(&socket2::SockAddr::unix(endpoint(address)?)?, duration)?;
    let mut peer = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of_val(&peer) as libc::socklen_t;
    // SAFETY: live socket fd and correctly sized initialized output buffer.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error().into());
    }
    anyhow::ensure!(
        len as usize == std::mem::size_of_val(&peer) && peer.pid > 0,
        "system bus peer PID is unavailable in this PID namespace"
    );
    // D-Bus PIDs are numbers in the broker's namespace, not necessarily ours.
    let broker_pidns = File::open(format!("/proc/{}/ns/pid", peer.pid))?;
    let our_pidns = File::open("/proc/thread-self/ns/pid")?;
    anyhow::ensure!(
        same_namespace(&broker_pidns, &our_pidns)?,
        "managed DNS requires the system bus in the same PID namespace"
    );
    remaining(until)?;
    let guid = authentication_guid(&socket, until)?;
    pin_address(address, &guid)?;
    Ok((socket, peer, guid))
}
fn busctl() -> &'static str {
    ["/usr/bin/busctl", "/bin/busctl"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or("busctl")
}

fn payload(
    operation: &str,
    index: i32,
    values: &[String],
) -> anyhow::Result<(&'static str, &'static str, Vec<String>)> {
    let mut args = vec![index.to_string()];
    match operation {
        "revert" => {
            anyhow::ensure!(values.is_empty(), "revert takes no resolver values");
            Ok(("RevertLink", "i", args))
        }
        "domain" => {
            args.push(values.len().to_string());
            for value in values {
                let (name, route_only) = value
                    .strip_prefix('~')
                    .map_or((value.as_str(), false), |v| (v, true));
                anyhow::ensure!(
                    !name.is_empty() && !name.contains('\0'),
                    "invalid resolver routing domain"
                );
                args.extend([name.to_string(), route_only.to_string()]);
            }
            Ok(("SetLinkDomains", "ia(sb)", args))
        }
        "dns" => {
            let servers = values
                .iter()
                .map(|value| -> anyhow::Result<_> {
                    let (address, port) = match value.split_once('#') {
                        Some((address, port)) => (address, port.parse::<u16>()?),
                        None => (value.as_str(), 53),
                    };
                    anyhow::ensure!(port > 0, "resolver port must be nonzero");
                    Ok((address.parse::<std::net::IpAddr>()?, port))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let extended = servers.iter().any(|(_, port)| *port != 53);
            args.push(servers.len().to_string());
            for (address, port) in servers {
                let (family, bytes) = match address {
                    std::net::IpAddr::V4(ip) => (libc::AF_INET, ip.octets().to_vec()),
                    std::net::IpAddr::V6(ip) => (libc::AF_INET6, ip.octets().to_vec()),
                };
                args.extend([family.to_string(), bytes.len().to_string()]);
                args.extend(bytes.iter().map(u8::to_string));
                if extended {
                    args.extend([port.to_string(), String::new()]);
                }
            }
            Ok(if extended {
                ("SetLinkDNSEx", "ia(iayqs)", args)
            } else {
                ("SetLinkDNS", "ia(iay)", args)
            })
        }
        _ => anyhow::bail!("unsupported resolver operation"),
    }
}

fn call(address: &str, method: &str, args: &[&str], until: Instant) -> anyhow::Result<String> {
    remaining(until)?;
    let output = Command::new(busctl())
        .args([
            "--no-pager",
            "--auto-start=no",
            &format!("--address={address}"),
            "call",
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            method,
        ])
        .args(args)
        .output_until(until)?;
    remaining(until)?;
    anyhow::ensure!(
        output.status.success(),
        "cannot verify DNS system bus {method}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    anyhow::ensure!(
        output.stdout.len() <= 1024,
        "oversized DNS system bus reply"
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}
fn string(reply: &str) -> anyhow::Result<String> {
    let value = reply
        .strip_prefix("s \"")
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| anyhow::anyhow!("invalid DNS system bus string reply"))?;
    anyhow::ensure!(
        !value.is_empty()
            && value.is_ascii()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b)),
        "invalid DNS system bus identity"
    );
    Ok(value.into())
}
fn service(address: &str, name: &str, until: Instant) -> anyhow::Result<Service> {
    let owner = string(&call(address, "GetNameOwner", &["s", name], until)?)?;
    anyhow::ensure!(
        owner.len() <= 255
            && owner.starts_with(':')
            && owner[1..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            && owner[1..].split('.').count() >= 2
            && owner[1..].split('.').all(|s| !s.is_empty()),
        "DNS service has no unique bus owner"
    );
    let reply = call(address, "GetConnectionUnixProcessID", &["s", &owner], until)?;
    let pid = reply
        .strip_prefix("u ")
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|p| *p > 0 && *p <= i32::MAX as u32)
        .ok_or_else(|| anyhow::anyhow!("invalid DNS service PID"))?;
    Ok(Service { owner, pid })
}
fn observe(address: &str, network: &File, until: Instant) -> anyhow::Result<Snapshot> {
    remaining(until)?;
    anyhow::ensure!(
        same_namespace(network, &File::open("/proc/thread-self/ns/net")?)?,
        "DNS caller network namespace changed"
    );
    let (_socket, peer, _) = bus_peer(address, until)?;
    let bus_id = string(&call(address, "GetId", &[], until)?)?;
    anyhow::ensure!(
        bus_id.len() == 32 && bus_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid DNS bus ID"
    );
    let resolved = service(address, RESOLVED, until)?;
    let _service_network = File::open(format!("/proc/{}/ns/net", resolved.pid))?;
    anyhow::ensure!(
        same_namespace(network, &_service_network)?,
        "DNS service {} is in a different network namespace; refusing numeric link commands",
        resolved.owner
    );
    anyhow::ensure!(
        service(address, RESOLVED, until)? == resolved
            && string(&call(address, "GetId", &[], until)?)? == bus_id,
        "DNS service changed during context verification"
    );
    let (_last_socket, last_peer, _) = bus_peer(address, until)?;
    anyhow::ensure!(
        (peer.pid, peer.uid, peer.gid) == (last_peer.pid, last_peer.uid, last_peer.gid),
        "system bus peer changed during DNS verification"
    );
    anyhow::ensure!(
        same_namespace(network, &File::open("/proc/thread-self/ns/net")?)?,
        "DNS caller namespace changed during verification"
    );
    remaining(until)?;
    Ok(Snapshot { bus_id, resolved })
}

#[cfg(test)]
#[path = "resolver_context_tests.rs"]
mod tests;
