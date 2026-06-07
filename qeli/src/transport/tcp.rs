use std::os::fd::AsRawFd;
use tokio::net::TcpStream;

/// Enable TCP keepalive on `stream` with `secs` idle time (Linux socket opts).
pub fn set_tcp_keepalive(stream: &TcpStream, secs: u64) -> std::io::Result<()> {
    // 0 = leave keepalive at the OS default (don't enable). Setting TCP_KEEPIDLE
    // to 0 returns EINVAL, which previously broke every connection when the
    // config's keepalive_secs was missing/zero.
    if secs == 0 {
        return Ok(());
    }
    let fd = stream.as_raw_fd();
    let keepalive: libc::c_int = 1;
    let keepidle: libc::c_int = secs as libc::c_int;
    let keepintvl: libc::c_int = (secs / 3).max(10) as libc::c_int;
    let keepcnt: libc::c_int = 3;
    unsafe {
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &keepalive as *const _ as *const libc::c_void,
            std::mem::size_of_val(&keepalive) as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            &keepidle as *const _ as *const libc::c_void,
            std::mem::size_of_val(&keepidle) as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            &keepintvl as *const _ as *const libc::c_void,
            std::mem::size_of_val(&keepintvl) as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &keepcnt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&keepcnt) as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
