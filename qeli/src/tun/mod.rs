#[cfg(target_os = "linux")]
pub mod iface;
pub mod tap;

pub use iface::DeviceType;
pub use tap::{
    generate_mac, is_tap_mode, prepend_ethernet_header, strip_ethernet_header, tap_interface_name,
};
