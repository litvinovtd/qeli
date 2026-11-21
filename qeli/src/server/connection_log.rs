//! Socket facts for lifecycle logging. Never infer the physical ingress interface
//! from the TUN name, the return route, or the address a wildcard listener binds to.
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(super) struct ConnectionLog {
    id: u64,
    transport: &'static str,
    peer: SocketAddr,
    listener: Option<SocketAddr>,
    local: Option<SocketAddr>,
    ingress_ifindex: u32,
}

tokio::task_local! {
    // Keep the accept context across obfs/REALITY/H2 wrapping of the TCP stream.
    pub(super) static TCP_CONNECTION_LOG: ConnectionLog;
}

impl ConnectionLog {
    pub(super) fn new(
        transport: &'static str,
        peer: SocketAddr,
        listener: Option<SocketAddr>,
        local: Option<SocketAddr>,
        ingress_ifindex: u32,
    ) -> Self {
        Self {
            id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            transport,
            peer,
            listener,
            local: local.filter(|addr| !addr.ip().is_unspecified()),
            ingress_ifindex,
        }
    }

    pub(super) fn authenticated(
        &self,
        event: fmt::Arguments<'_>,
        profile: &str,
        tun: &str,
        session: u64,
        user: &str,
        tunnel_ip: std::net::IpAddr,
    ) {
        log::info!(
            "{event} {self} profile={profile:?} tun={tun:?} session={session} user={} tunnel_ip={tunnel_ip}",
            quoted_user(user)
        );
    }
}

fn quoted_user(username: &str) -> impl fmt::Display + '_ {
    struct Quoted<'a>(&'a str);
    impl fmt::Display for Quoted<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&self.0, f)
        }
    }
    Quoted(username)
}

pub(super) fn authenticated_tcp(
    event: fmt::Arguments<'_>,
    profile: &str,
    tun: &str,
    session: u64,
    user: &str,
    tunnel_ip: std::net::IpAddr,
) {
    let _ = TCP_CONNECTION_LOG.try_with(|connection| {
        connection.authenticated(event, profile, tun, session, user, tunnel_ip);
    });
}

impl fmt::Display for ConnectionLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pid={} conn={} transport={} peer={} listener=",
            std::process::id(),
            self.id,
            self.transport,
            self.peer
        )?;
        match self.listener {
            Some(addr) => write!(f, "{addr}")?,
            None => f.write_str("unknown")?,
        }
        f.write_str(" local=")?;
        match self.local {
            Some(addr) => write!(f, "{addr}")?,
            None => f.write_str("unknown")?,
        }
        if self.ingress_ifindex == 0 {
            f.write_str(" ingress_ifindex=unknown")
        } else {
            write!(f, " ingress_ifindex={}", self.ingress_ifindex)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_bound_and_actual_endpoints_separately() {
        let peer = "[2001:db8::2]:12345".parse().unwrap();
        let listener = "[::]:443".parse().unwrap();
        let local = "[2001:db8::1]:443".parse().unwrap();
        let udp = ConnectionLog::new("udp", peer, Some(listener), Some(local), 7);
        assert!(udp.to_string().ends_with("transport=udp peer=[2001:db8::2]:12345 listener=[::]:443 local=[2001:db8::1]:443 ingress_ifindex=7"));
        let tcp = ConnectionLog::new("tcp", peer, Some(listener), Some(listener), 0);
        assert!(tcp
            .to_string()
            .ends_with("listener=[::]:443 local=unknown ingress_ifindex=unknown"));
        assert_ne!(udp.id, tcp.id);
    }

    #[test]
    fn real_user_is_visible_but_cannot_inject_log_lines() {
        assert_eq!(quoted_user("alice").to_string(), r#""alice""#);
        assert_eq!(
            quoted_user("alice\r\nuser=\"root\"").to_string(),
            r#""alice\r\nuser=\"root\"""#
        );
    }

    #[tokio::test]
    async fn wildcard_tcp_listener_preserves_each_accepted_destination() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let first = SocketAddr::from(([127, 0, 0, 2], bound.port()));
        let second = SocketAddr::from(([127, 0, 0, 3], bound.port()));
        let listener = &listener;
        let get_context = |target| async move {
            let (client, accepted) = tokio::join!(TcpStream::connect(target), listener.accept());
            let _client = client.unwrap();
            let (stream, peer) = accepted.unwrap();
            ConnectionLog::new("tcp", peer, Some(bound), stream.local_addr().ok(), 0)
        };
        let a = get_context(first).await;
        let b = get_context(second).await;
        let (a_local, b_local) = tokio::join!(
            TCP_CONNECTION_LOG.scope(a, async {
                tokio::task::yield_now().await;
                TCP_CONNECTION_LOG.with(|value| value.local)
            }),
            TCP_CONNECTION_LOG.scope(b, async {
                tokio::task::yield_now().await;
                TCP_CONNECTION_LOG.with(|value| value.local)
            })
        );
        assert_eq!((a_local, b_local), (Some(first), Some(second)));
        assert!(TCP_CONNECTION_LOG.try_with(|_| ()).is_err());
    }
}
