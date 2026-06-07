pub mod tcp;
pub mod udp;

/// Wire transport of a server profile / client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportProtocol::Tcp => write!(f, "tcp"),
            TransportProtocol::Udp => write!(f, "udp"),
        }
    }
}

impl std::str::FromStr for TransportProtocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(TransportProtocol::Tcp),
            "udp" => Ok(TransportProtocol::Udp),
            _ => Err(format!("unknown transport protocol: {}", s)),
        }
    }
}
