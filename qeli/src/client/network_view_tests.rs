//! Native caller regression with a sysfs mount inherited from another namespace.
use super::*;
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_tap_mac_and_hook_index_use_calling_namespace() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        // SAFETY: this new disposable thread has no application state.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let name = "qeli-view1";
        anyhow::ensure!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
        let tun = crate::tun::iface::TunInterface::create_tap(name, 1400)?;
        let output = crate::system_command::Command::new("ip")
            .args(["link", "set", name, "address", "02:12:34:56:78:9b"])
            .output()?;
        anyhow::ensure!(output.status.success());
        anyhow::ensure!(read_interface_mac(name)? == [2, 0x12, 0x34, 0x56, 0x78, 0x9b]);
        let index = hook_if_index(name).parse::<u32>()?;
        anyhow::ensure!(index > 0);
        anyhow::ensure!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
        drop(tun);
        anyhow::ensure!(hook_if_index(name).is_empty());
        Ok(())
    })
    .join()
    .expect("native TAP observation test panicked")
}
