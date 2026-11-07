//! Independent rollback admission. The watchdog shares neither VPN lifecycle
//! nor the reconciler's lifetime lock, and serializes only short network writes.
use super::*;
use std::os::fd::AsRawFd;
#[derive(Serialize, Deserialize)]
struct Pending {
    boot: String,
    token: String,
    deadline_ms: u64,
    policy: PathBuf,
    state: PathBuf,
    previous: Vec<u8>,
    candidate: Vec<u8>,
}
fn now() -> Result<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } == 0,
        "boottime unavailable"
    );
    Ok(t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000)
}
fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
pub(super) fn mutation_lock(directory: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("mutation.lock"))?;
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "router transaction already active"
    );
    Ok(file)
}
async fn wait_lock(directory: &Path, seconds: u64) -> Result<fs::File> {
    let until = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        match mutation_lock(directory) {
            Ok(lock) => return Ok(lock),
            Err(error) => {
                if tokio::time::Instant::now() >= until {
                    return Err(error);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
pub(super) fn publish_worker(directory: &Path, policy: &[u8]) -> Result<()> {
    let ready = directory.join("ready.json");
    if ready.exists() {
        fs::remove_file(ready)?;
    }
    let pid = std::process::id();
    write_private(
        &directory.join("worker.json"),
        &serde_json::to_vec(
            &json!({"pid":pid,"start":status::generation(pid),"boot":boot()?,"policy_sha256":digest(policy)}),
        )?,
    )
}
fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    sha2::Sha256::digest(bytes)
        .iter()
        .flat_map(|b| {
            [
                HEX[(b >> 4) as usize] as char,
                HEX[(b & 15) as usize] as char,
            ]
        })
        .collect()
}
pub(super) fn publish_ready(directory: &Path) -> Result<()> {
    write_private(
        &directory.join("ready.json"),
        &read_private(&directory.join("worker.json"), 1024)?,
    )
}
fn worker(p: &Policy) -> Result<Option<u32>> {
    let path = p.state_directory.join("worker.json");
    if !path.exists() {
        return Ok(None);
    }
    let v: Value = serde_json::from_slice(&read_private(&path, 1024)?)?;
    let pid = u32::try_from(v["pid"].as_u64().context("invalid policy PID")?)?;
    ensure!(pid > 1, "invalid router worker receipt");
    if v["boot"] != boot()? {
        return Ok(None);
    }
    let Some(start) = status::generation(pid) else {
        return Ok(None);
    };
    if v["start"] != start {
        return Ok(None);
    }
    let expected = fs::metadata(std::env::current_exe()?)?;
    let actual = fs::metadata(format!("/proc/{pid}/exe"))?;
    ensure!(
        expected.dev() == actual.dev() && expected.ino() == actual.ino(),
        "router worker executable changed; review required"
    );
    Ok(Some(pid))
}
pub(super) async fn start(path: &Path) -> Result<()> {
    let p: Policy = serde_json::from_slice(&read_private(path, 65536)?)?;
    p.validate()?;
    private_dir(&p.state_directory, true)?;
    let marker = path.with_extension("enabled");
    if fs::symlink_metadata(&marker).is_ok() {
        ensure!(
            read_private(&marker, 64)?.as_slice() == b"qeli-router-v1",
            "foreign policy activation marker"
        );
    }
    if p.components.routing == Owner::Client || p.components.firewall == Owner::Client {
        write_private(&marker, b"qeli-router-v1")?;
    }
    if worker(&p)?.is_some() {
        let current: Value =
            serde_json::from_slice(&read_private(&p.state_directory.join("worker.json"), 1024)?)?;
        if current["policy_sha256"] == digest(&read_private(path, 65536)?) {
            return Ok(());
        }
        stop(path).await?;
    }
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(["router", "run", "--policy"])
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    for _ in 0..300 {
        if worker(&p)? == Some(child.id())
            && read_private(&p.state_directory.join("ready.json"), 1024).ok()
                == read_private(&p.state_directory.join("worker.json"), 1024).ok()
        {
            return Ok(());
        }
        if let Some(code) = child.try_wait()? {
            ensure!(
                code.success(),
                "router policy worker failed admission (use router check/run for details)"
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("router policy worker not ready")
}
pub(super) async fn disable(path: &Path) -> Result<()> {
    stop(path).await?;
    let _namespace = policy::namespace_lock()?;
    let mut p: Policy = serde_json::from_slice(&read_private(path, 65536)?)?;
    p.validate()?;
    private_dir(&p.state_directory, false)?;
    let _lock = wait_lock(&p.state_directory, 10).await?;
    let pending = p.state_directory.join("pending.json");
    // Cancel the watchdog before explicit cleanup: it must not resurrect an old
    // managed policy after the operator deliberately selected external ownership.
    if pending.exists() {
        fs::remove_file(&pending)?;
    }
    let receipt = p.state_directory.join("receipt.json");
    if receipt.exists() {
        let r: policy::Receipt = serde_json::from_slice(&read_private(&receipt, 8192)?)?;
        policy::cleanup(&r).await?;
        fs::remove_file(receipt)?;
    }
    p.components = Components::default();
    guard::remove(&p).await?;
    let bytes = serde_json::to_vec_pretty(&p)?;
    write_private(path, &bytes)?;
    write_private(&path.with_extension("confirmed.json"), &bytes)?;
    let marker = path.with_extension("enabled");
    if marker.exists() {
        ensure!(
            read_private(&marker, 64)?.as_slice() == b"qeli-router-v1",
            "foreign activation marker"
        );
        fs::remove_file(marker)?;
    }
    println!("External routing/firewall ownership restored; VPN process was not restarted");
    Ok(())
}
pub(super) async fn stop(path: &Path) -> Result<()> {
    let p: Policy = serde_json::from_slice(&read_private(path, 65536)?)?;
    if let Some(pid) = worker(&p)? {
        // Re-check immediately before signalling; never kill by unverified PID alone.
        ensure!(worker(&p)? == Some(pid), "router worker generation changed");
        ensure!(
            unsafe { libc::kill(pid as i32, libc::SIGTERM) } == 0,
            "cannot stop policy worker"
        );
        for _ in 0..100 {
            if worker(&p)?.is_none() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("router policy worker did not finish; rules retained");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connect_disconnect_does_not_require_reapproving_network_policy() {
        let p = Policy::default();
        let mut stopped = p.clone();
        stopped.client_disabled = true;
        assert_eq!(intent(&p).unwrap(), intent(&stopped).unwrap());
        stopped.components.firewall = Owner::Client;
        assert_ne!(intent(&p).unwrap(), intent(&stopped).unwrap());
    }
}
fn intent(p: &Policy) -> Result<Value> {
    let mut v = serde_json::to_value(p)?;
    // Connect/disconnect is live intent, not a new network-policy transaction.
    v.as_object_mut()
        .context("policy object")?
        .remove("client_disabled");
    Ok(v)
}
pub(super) fn admit_render(path: &Path, p: &Policy) -> Result<()> {
    let pending = p.state_directory.join("pending.json");
    if pending.exists() {
        let entry: Pending = serde_json::from_slice(&read_private(&pending, 150000)?)?;
        if entry.boot == boot()? {
            let old: Policy = serde_json::from_slice(&entry.candidate)?;
            ensure!(
                intent(&old)? == intent(p)?,
                "confirm or wait for rollback before changing a provisional router policy"
            );
        }
    }
    let rejected = path.with_extension("rejected.json");
    if rejected.exists()
        && (p.components.routing == Owner::Client || p.components.firewall == Owner::Client)
    {
        let failed: Policy = serde_json::from_slice(&read_private(&rejected, 65536)?)?;
        ensure!(intent(&failed)?!=intent(p)?,"this policy was rolled back; correct its settings before retrying (last accepted policy retained)");
    }
    Ok(())
}
pub(super) fn accept_external(path: &Path, p: &Policy, bytes: &[u8]) -> Result<()> {
    let pending = p.state_directory.join("pending.json");
    if pending.exists() {
        fs::remove_file(pending)?;
    }
    write_private(&path.with_extension("confirmed.json"), bytes)
}
pub(super) async fn arm(path: &Path, p: &Policy, candidate: &[u8]) -> Result<()> {
    let pending = p.state_directory.join("pending.json");
    if pending.exists() {
        let current: Pending = serde_json::from_slice(&read_private(&pending, 150000)?)?;
        if current.boot != boot()? {
            fs::remove_file(&pending)?;
        } else {
            ensure!(
                intent(&serde_json::from_slice::<Policy>(&current.candidate)?)? == intent(p)?
                    && current.deadline_ms > now()?,
                "unconfirmed/expired router transaction exists"
            );
            let mut current = current;
            current.candidate = candidate.into();
            write_private(&pending, &serde_json::to_vec(&current)?)?;
            return Ok(());
        }
    }
    let confirmed = path.with_extension("confirmed.json");
    let previous = if confirmed.exists() {
        read_private(&confirmed, 65536)?
    } else {
        let mut external = p.clone();
        external.components = Components::default();
        serde_json::to_vec(&external)?
    };
    let old: Policy = serde_json::from_slice(&previous)?;
    old.validate()?;
    if previous == candidate || intent(&old)? == intent(p)? {
        write_private(&confirmed, candidate)?;
        return Ok(());
    }
    let token = format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    );
    let entry = Pending {
        boot: boot()?,
        token: token.clone(),
        deadline_ms: now()? + 120000,
        policy: path.into(),
        state: p.state_directory.clone(),
        previous,
        candidate: candidate.into(),
    };
    write_private(&pending, &serde_json::to_vec(&entry)?)?;
    // Spawn watchdog before mutation; require its private ready receipt before
    // proceeding. Its process group/stdin do not depend on the SSH terminal.
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["router", "watchdog", "--pending"])
        .arg(&pending)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let ready = p.state_directory.join("watchdog-ready");
    for _ in 0..30 {
        if read_private(&ready, 128).ok().as_deref() == Some(token.as_bytes()) {
            println!("Router policy is provisional for 120 seconds; verify a fresh management connection, then run qeli-client router confirm --policy {}",path.display());
            return Ok(());
        }
        if child.try_wait()?.is_some() {
            bail!("rollback watchdog exited before admission");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("rollback watchdog did not confirm readiness")
}
pub(super) async fn confirm(path: &Path) -> Result<()> {
    let candidate = read_private(path, 65536)?;
    let p: Policy = serde_json::from_slice(&candidate)?;
    p.validate()?;
    private_dir(&p.state_directory, false)?;
    let _lock = wait_lock(&p.state_directory, 10).await?;
    let pending = p.state_directory.join("pending.json");
    let entry: Pending = serde_json::from_slice(&read_private(&pending, 150000)?)?;
    ensure!(
        entry.boot == boot()?
            && entry.candidate == candidate
            && entry.deadline_ms > now()?
            && entry.policy == path,
        "cannot confirm changed/stale router transaction"
    );
    write_private(&path.with_extension("confirmed.json"), &candidate)?;
    fs::remove_file(pending)?;
    println!("Router policy confirmed");
    Ok(())
}
pub(super) async fn watchdog(path: &Path) -> Result<()> {
    let entry: Pending = serde_json::from_slice(&read_private(path, 150000)?)?;
    ensure!(
        entry.boot == boot()? && entry.state == path.parent().context("pending parent")?,
        "invalid watchdog scope"
    );
    write_private(&entry.state.join("watchdog-ready"), entry.token.as_bytes())?;
    while now()? < entry.deadline_ms {
        match read_private(path, 150000) {
            Ok(bytes) => {
                let current: Pending = serde_json::from_slice(&bytes)?;
                if current.token != entry.token {
                    return Ok(());
                }
            }
            Err(e) if !path.exists() => {
                let _ = e;
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let latest: Pending = serde_json::from_slice(&read_private(path, 150000)?)?;
    if latest.token != entry.token {
        return Ok(());
    }
    let entry = latest;
    let _lock = wait_lock(&entry.state, 45).await?;
    // Serialize against confirmation and stop only our verified policy worker.
    // The kernel guard survives. Take the namespace lease before rollback so a
    // controller using another state directory cannot have its objects removed.
    let current: Pending = match read_private(path, 150000) {
        Ok(v) => serde_json::from_slice(&v)?,
        Err(_) if !path.exists() => return Ok(()),
        Err(e) => return Err(e),
    };
    if current.token != entry.token || read_private(&entry.policy, 65536)? != entry.candidate {
        return Ok(());
    }
    stop(&entry.policy).await?;
    let _namespace = policy::namespace_lock()?;
    write_private(
        &entry.policy.with_extension("rejected.json"),
        &entry.candidate,
    )?;
    write_private(&entry.policy, &entry.previous)?;
    let receipt = entry.state.join("receipt.json");
    let previous: Policy = serde_json::from_slice(&entry.previous)?;
    if receipt.exists() {
        let r: policy::Receipt = serde_json::from_slice(&read_private(&receipt, 8192)?)?;
        if previous.components.routing == Owner::Client {
            policy::restore_rollback(&previous, &r).await?;
        } else {
            policy::cleanup(&r).await?;
            fs::remove_file(receipt)?;
        }
    }
    let native = status::read(
        &previous.status_file,
        previous.pid_file.as_deref(),
        &previous.device,
    );
    let live =
        !previous.client_disabled && native["available"] == true && native["state"] == "connected";
    guard::Guard::default().sync(&previous, live, live).await?;
    write_private(
        &entry.policy.with_extension("confirmed.json"),
        &entry.previous,
    )?;
    fs::remove_file(path)?;
    write_private(
        &entry.state.join("rolled-back"),
        b"confirmation deadline expired",
    )?;
    drop(_namespace);
    drop(_lock);
    if (previous.components.routing == Owner::Client
        || previous.components.firewall == Owner::Client)
        && read_private(&entry.policy, 65536)? == entry.previous
    {
        start(&entry.policy).await?;
    }
    // The platform supervisor sees the restored file on respawn. Never restart
    // the VPN/data-plane process or change administrative SSH/firewall settings.
    Ok(())
}
