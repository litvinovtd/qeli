#[cfg(target_os = "linux")]
pub mod iface;
pub mod tap;

pub use iface::DeviceType;
pub use tap::{
    client_tap_control_reply, destination_mac_for_ip, is_tap_mode, mac_from_ip,
    prepend_ethernet_header, server_tap_control_reply, strip_ethernet_header, tap_interface_name,
    TapGateway,
};
