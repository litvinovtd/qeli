use tokio::net::TcpStream;

/// Enable TCP keepalive on `stream` with `secs` idle time.
///
/// The fine-grained idle/interval/count knobs (`TCP_KEEPIDLE`/`TCP_KEEPINTVL`/
/// `TCP_KEEPCNT`) are Linux-only. On other targets this is a best-effort no-op so
/// the crate still compiles — qeli's daemon/CLI ship for Linux (incl. Keenetic
/// musl), and the desktop clients are C# and never reach this path.
#[cfg(target_os = "linux")]
pub fn set_tcp_keepalive(stream: &TcpStream, secs: u64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
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

/// Non-Linux fallback: `TCP_KEEPIDLE`/`INTVL`/`CNT` don't exist, so keepalive
/// tuning is skipped (best-effort). Keeps a non-Linux build compiling.
#[cfg(not(target_os = "linux"))]
pub fn set_tcp_keepalive(_stream: &TcpStream, _secs: u64) -> std::io::Result<()> {
    Ok(())
}
