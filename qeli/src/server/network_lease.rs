//! Cooperative server-worker admission for one Linux network namespace.
//! A control socket path is not network ownership: custom paths and private /run
//! mounts can coexist while sharing the rules swept by NAT startup recovery.
//! Abstract sockets are scoped by the kernel network namespace, released at
//! process death, and never unlinked. They do not claim authority over old binaries
//! or external firewall managers; durable exact-rule recovery is separate.
use std::{
    io,
    os::{
        fd::IntoRawFd,
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixDatagram},
    },
};

const NAME: &[u8] = b"qeli.server.worker";

/// An interrupted worker cannot prove its async children have stopped. Keep the
/// namespace reservation until process exit rather than admitting a replacement
/// over its possibly live TUN/firewall resources.
pub(super) struct WorkerLease {
    socket: Option<UnixDatagram>,
    armed: bool,
}

impl WorkerLease {
    pub(super) fn arm(&mut self) {
        self.armed = true;
    }

    /// Called only after every profile, service and final cleanup has completed.
    /// The socket itself still lives until the worker's outer scope is dropped.
    pub(super) fn mark_complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        if self.armed {
            if let Some(socket) = self.socket.take() {
                // FD_CLOEXEC is retained. The intentionally unowned descriptor
                // keeps the abstract address bound only in this process.
                let _ = socket.into_raw_fd();
                log::error!(
                    "server worker ended without confirmed terminal cleanup; network namespace reservation retained until process exit"
                );
            }
        }
    }
}

pub(super) fn acquire() -> anyhow::Result<WorkerLease> {
    reserve(NAME).map_err(|error| anyhow::anyhow!(
        "server worker network namespace already owned or reservation unavailable: {error}; stop the other worker or use a separate network namespace (a different control socket path is not isolation)"
    ))
}

fn reserve(name: &[u8]) -> io::Result<WorkerLease> {
    Ok(WorkerLease {
        socket: Some(bind(name)?),
        armed: false,
    })
}

fn bind(name: &[u8]) -> io::Result<UnixDatagram> {
    // Rust's socket constructor sets close-on-exec. No messages or listening
    // backlog are needed: one live bound datagram socket excludes every peer.
    UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name)?)
}

#[cfg(test)]
#[path = "network_lease_tests.rs"]
mod tests;
