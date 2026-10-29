use super::control_socket::ControlSocket;
use crate::config::users::UsersDb;
use crate::control_io::{self, IO_TIMEOUT, MAX_REQUEST, MAX_RESPONSE, RESPONSE_TIMEOUT};
use crate::server::{ProfileRuntime, ServerState};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Default control-socket path. Override with `QELI_CONTROL_SOCKET` — see
/// [`control_socket_path`].
pub const CONTROL_SOCKET: &str = "/var/run/qeli/control.sock";

/// The control socket this process binds / connects to.
///
/// Every CLI subcommand advertises a `--socket` flag, but the SERVER always bound the
/// constant, so pointing the flag anywhere else could only ever fail to connect: the flag
/// was, in effect, decoration. That also made two qeli instances on one host impossible
/// in separate network namespaces (they fight over a shared filesystem path) and blocked
/// any non-root run, where `/var/run` is not
/// writable. Honouring one environment variable on BOTH sides makes the flag mean
/// something without inventing a config key that has no natural section to live in — the
/// systemd unit or a shell can set it, and the CLI inherits the same default.
/// Workers still share a namespace-wide admission lease: a custom control path does not
/// permit concurrent workers to sweep each other's firewall in the same network namespace.
/// (Audit 2026-07-27, S3; namespace admission follow-up 2026-09-24.)
pub fn control_socket_path() -> String {
    std::env::var("QELI_CONTROL_SOCKET")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| CONTROL_SOCKET.to_string())
}

/// Return a mutable external entry, materializing an inline user as a file override when
/// a runtime control command needs to persist a change.
fn external_or_inline_user<'a>(
    db: &'a mut UsersDb,
    config: &crate::config::server::ServerConfig,
    username: &str,
) -> Option<&'a mut crate::config::users::UserEntry> {
    if db.users.iter().all(|user| user.username != username) {
        let inline = config
            .auth
            .users
            .iter()
            .find(|user| user.username == username)
            .cloned()?;
        db.users.push(inline);
    }
    db.users.iter_mut().find(|user| user.username == username)
}

fn usage_reset_failure(error: &anyhow::Error) -> String {
    if crate::util::atomic_write_was_published(error) {
        format!("usage reset was published, but its durability could not be confirmed: {error:#}")
    } else {
        format!("usage counter was not reset because it could not be persisted: {error:#}")
    }
}

/// Keep live auth aligned with a published INI even if its directory sync failed.
fn users_write_failure(
    config: &crate::config::server::ServerConfig,
    users: &mut UsersDb,
    error: &anyhow::Error,
) -> String {
    let mut message = crate::config::users::users_error_message(error);
    if crate::util::atomic_write_was_published(error) {
        match crate::server::load_users_db_for_runtime(config) {
            Ok(fresh) => {
                *users = fresh;
                message.push_str("; published users read back into live auth");
            }
            Err(readback) => message.push_str(&format!(
                "; readback failed: {}",
                crate::config::users::users_error_message(&readback)
            )),
        }
    } else {
        message.push_str("; users file change NOT applied");
    }
    message
}

#[derive(Deserialize)]
struct Request {
    cmd: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    mbps: u32,
    #[serde(default)]
    data_limit_gb: u64,
    #[serde(default)]
    expire_at: Option<i64>,
    /// IP address argument (for unblock).
    #[serde(default)]
    ip: String,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clients: Option<Vec<ClientInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// One blocked IP for the list-blocked response. Serialized as a JSON array into
/// `Response.message` (so no other `Response {..}` literal needs a new field).
#[derive(Serialize)]
pub struct BlockedInfo {
    pub ip: String,
    pub failures: u32,
    pub unblock_in_secs: u64,
}

#[derive(Serialize)]
pub struct ClientInfo {
    pub profile: String,
    pub username: String,
    /// Stable primary address retained for older clients of the control API.
    pub ip: String,
    /// Every address assigned to this session, in deterministic IPv4/IPv6 order.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Client's public source address (ip:port).
    pub peer: String,
    pub connected_secs: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    /// Outbound packets dropped by writer-channel backpressure (rate-limit / slow
    /// client) — 0 in the healthy case.
    #[serde(default)]
    pub dropped: u64,
    pub bandwidth_limit_mbps: u32,
    /// Active bonded (multipath) streams — 1 for a single-link session.
    #[serde(default)]
    pub streams: u32,
    /// What the client SAYS it is — self-reported over the tunnel, never attested. `None`
    /// for a client that predates the report, or one whose report failed validation.
    /// `serde(default)` so a new CLI still parses an older server's reply, as with
    /// `dropped`/`streams`.
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default)]
    pub client_platform: Option<String>,
}

/// Bind and secure the control socket before the data plane starts. A worker without this
/// socket is not manageable by the supervisor, so bind failures must be startup failures,
/// not errors hidden in a detached task.
pub(super) fn bind_control_server() -> anyhow::Result<ControlSocket> {
    let sock = control_socket_path();
    let listener = ControlSocket::bind(std::path::Path::new(&sock))?;
    log::info!("Control socket listening on {}", sock);
    Ok(listener)
}

pub(super) async fn run_control_server(
    state: Arc<ServerState>,
    listener: tokio::net::UnixListener,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut handlers = tokio::task::JoinSet::new();
    let result = loop {
        // Completed handlers count towards the cap until reaped. At capacity the
        // accept branch is disabled, but shutdown and task completion remain live.
        tokio::select! {
            biased;
            _ = crate::server_supervisor::wait_for_shutdown(&mut shutdown) => break Ok(()),
            joined = handlers.join_next(), if !handlers.is_empty() => {
                if let Some(Err(error)) = joined {
                    log::warn!("Control handler task panicked: {error}");
                }
            }
            accepted = listener.accept(), if handlers.len() < 16 => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => break Err(anyhow::anyhow!("control accept failed: {error}")),
                };
                let state = state.clone();
                handlers.spawn(async move {
                    if let Err(error) = handle_control(stream, state).await {
                        log::debug!("Control handler error: {error}");
                    }
                });
            }
        }
    };
    // Close admission. The worker keeps the pathname lease until all handlers
    // and profiles finish. Do not cancel a disk/runtime update at
    // an arbitrary await. The worker supervisor retains its process grace limit.
    drop(listener);
    while let Some(joined) = handlers.join_next().await {
        if let Err(error) = joined {
            log::warn!("Control handler task panicked: {error}");
        }
    }
    result
}

async fn handle_control(
    mut stream: tokio::net::UnixStream,
    state: Arc<ServerState>,
) -> anyhow::Result<()> {
    let (reader, writer) = stream.split();
    let Some(line) = control_io::read_line(reader, MAX_REQUEST, IO_TIMEOUT).await? else {
        return Ok(());
    };
    let resp = match serde_json::from_str::<Request>(&line) {
        Ok(req) => dispatch(req, &state).await,
        Err(e) => Response {
            ok: false,
            error: Some(format!("invalid JSON: {}", e)),
            clients: None,
            message: None,
        },
    };
    let out = serde_json::to_string(&resp)?;
    control_io::write_line(writer, &out, MAX_RESPONSE, IO_TIMEOUT).await?;
    Ok(())
}

/// Forcefully kick every session of `username` on one profile.
///
/// Drops the session(s) from the registry FIRST (so `list-clients` / the panel
/// reflect the kick immediately even when a stream task is blocked writing to a
/// half-dead client) and frees their pool IPs, THEN signals the tasks to exit.
/// Without the up-front removal a cooperative kick signal alone leaves a stuck
/// session lingering in the panel and its IP held — the reported "kicked user
/// stays connected and can't reconnect". The stuck task's own later cleanup is a
/// no-op (its `by_ip` guard no longer matches). Returns the number kicked.
async fn kick_user_on_profile(profile: &Arc<ProfileRuntime>, username: &str) -> usize {
    kick_matching_sessions_on_profile(profile, |session| session.username == username).await
}

async fn kick_matching_sessions_on_profile(
    profile: &Arc<ProfileRuntime>,
    mut should_kick: impl FnMut(&crate::server::handler::SessionShared) -> bool,
) -> usize {
    // Kicking is an authoritative session/lease transition, just like authentication.
    // Hold admission until every removed session has released its device lease so a
    // same-device reconnect cannot reclaim the lease in the removal->release gap.
    let _admission_guard = profile.admission.lock().await;
    let (kicked, iroutes) = {
        let mut sessions = profile.sessions.write().await;
        let ips: Vec<std::net::IpAddr> = sessions
            .by_ip
            .iter()
            .filter(|(_, s)| should_kick(s))
            .map(|(ip, _)| *ip)
            .collect();
        let mut out = Vec::with_capacity(ips.len());
        let mut iroutes: Vec<String> = Vec::new();
        for ip in ips {
            if let Some(s) = sessions.remove(ip) {
                iroutes.extend(sessions.take_client_routes(ip));
                out.push(s);
            }
        }
        (out, iroutes)
    };
    // Tear down the kicked sessions' inbound iroutes now the sessions lock is gone, but
    // before admission is released. A detached delete can otherwise run after a reconnect
    // has installed the same CIDR and remove the new session's route.
    for cidr in &iroutes {
        let _ = crate::server::handler::program_client_subnet_route(
            false,
            cidr,
            &profile.config.tun.name,
        )
        .await;
    }
    #[cfg(feature = "experimental-roaming")]
    for session in &kicked {
        let event =
            crate::protocol::control_v2::ManagementEvent::Kick(crate::protocol::control_v2::Kick {
                reason: crate::protocol::control_v2::KickReason::Administrative,
                message: "Disconnected by the server administrator".to_string(),
                reconnect_allowed: false,
            });
        let _ = session.send_management(&event).await;
    }
    for s in &kicked {
        s.kick_all();
        profile.pool.lock().await.release(&s.device_key);
        // Notify (opt-in): admin-kicked. Per-user throttle coalesces a multi-session
        // kick into one alert; already out of by_ip so no teardown double-fire.
        crate::server::notify::fire_disconnect(&s.username, &profile.name, s.peer);
    }
    kicked.len()
}

/// Apply current access policy, per-profile device caps and bandwidth to open sessions.
/// Compiled packet permissions require reconnect when changed. The existing kick
/// path owns admission, iroutes, ingress revocation and pool release.
pub(super) async fn apply_user_policy_to_sessions(state: &Arc<ServerState>) -> usize {
    let profiles: Vec<_> = state.profiles.read().await.values().cloned().collect();
    let mut count = 0;
    for profile in profiles {
        let denied: std::collections::HashSet<u64> = {
            // Admission takes the users lock too. Acquire admission FIRST so a
            // queued users writer cannot deadlock this scan against authentication.
            let _admission_guard = profile.admission.lock().await;
            let users = state.users_db.read().await;
            let sessions = profile.sessions.read().await;
            let mut denied = std::collections::HashSet::new();
            let mut by_user: std::collections::HashMap<&str, Vec<_>> =
                std::collections::HashMap::new();
            for session in sessions.by_ip.values() {
                let Some(user) = users
                    .find_user(&session.username)
                    .filter(|user| user.allowed_on_profile(&profile.name))
                else {
                    denied.insert(session.session_id);
                    continue;
                };
                session.bandwidth_limit_mbps.store(
                    user.effective_bandwidth_limit(&users.groups),
                    std::sync::atomic::Ordering::Relaxed,
                );
                if !crate::server::handler::session_access_policy_matches(
                    &profile.config,
                    &users,
                    session,
                ) {
                    denied.insert(session.session_id);
                    continue;
                }
                by_user.entry(&session.username).or_default().push(session);
            }
            for (username, mut live) in by_user {
                let cap = users
                    .find_user(username)
                    .expect("authorized user above")
                    .effective_max_sessions(&users.groups);
                if cap > 0 && live.len() > cap as usize {
                    // Match admission: newest devices win. IDs break equal-time ties.
                    live.sort_unstable_by_key(|session| {
                        std::cmp::Reverse((session.connected_at, session.session_id))
                    });
                    denied.extend(
                        live.into_iter()
                            .skip(cap as usize)
                            .map(|session| session.session_id),
                    );
                }
            }
            denied
        };
        if !denied.is_empty() {
            // The snapshot cannot kick a replacement session admitted in this gap.
            count += kick_matching_sessions_on_profile(&profile, |session| {
                denied.contains(&session.session_id)
            })
            .await;
        }
    }
    count
}

/// Snapshot worker-lifetime roaming outcomes without exposing session locators, CIDs or proofs.
async fn roaming_status(state: &Arc<ServerState>) -> serde_json::Value {
    let profiles = state.profiles.read().await;
    let mut ordered = profiles.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(name, _)| *name);
    let mut out = Vec::with_capacity(ordered.len());

    for (name, profile) in ordered {
        let tcp = profile.tcp_roaming_metrics.snapshot();
        #[cfg(feature = "experimental-roaming")]
        let (
            tcp_sessions,
            orphaned_sessions,
            orphaned_bytes,
            udp_attempts,
            udp_commits,
            udp_failures,
            udp_sessions,
            udp_candidates,
            udp_cid_aliases,
        ) = {
            let tcp_sessions = profile
                .sessions
                .read()
                .await
                .by_ip
                .values()
                .filter(|session| session.tcp_roaming.is_some())
                .count();
            let (orphaned_sessions, orphaned_bytes) = {
                let limiter = crate::server::lock_or_recover(
                    &profile.tcp_orphans,
                    "control::roaming_tcp_orphans",
                );
                (limiter.sessions(), limiter.bytes())
            };
            let udp = profile.udp_roaming_registry.stats();
            (
                tcp_sessions,
                orphaned_sessions,
                orphaned_bytes,
                udp.attempts_total,
                udp.commits_total,
                udp.failures_total,
                udp.active_sessions,
                udp.active_candidates,
                udp.cid_aliases,
            )
        };
        #[cfg(not(feature = "experimental-roaming"))]
        let (
            tcp_sessions,
            orphaned_sessions,
            orphaned_bytes,
            udp_attempts,
            udp_commits,
            udp_failures,
            udp_sessions,
            udp_candidates,
            udp_cid_aliases,
        ) = (
            0usize, 0usize, 0usize, 0u64, 0u64, 0u64, 0usize, 0usize, 0usize,
        );

        out.push(serde_json::json!({
            "name": name,
            "enabled": profile.config.roaming.enabled,
            "feature_compiled": cfg!(feature = "experimental-roaming"),
            "transport": profile.config.bind.transport,
            "worker_lifetime": true,
            "tcp": {
                "attempts_total": tcp.attempts_total,
                "commits_total": tcp.commits_total,
                "failures_total": tcp.failures_total,
                "grace_expired_total": tcp.grace_expired_total,
                "active_sessions": tcp_sessions,
                "orphaned_sessions": orphaned_sessions,
                "orphaned_bytes": orphaned_bytes,
            },
            "udp": {
                "attempts_total": udp_attempts,
                "commits_total": udp_commits,
                "failures_total": udp_failures,
                "active_sessions": udp_sessions,
                "active_candidates": udp_candidates,
                "cid_aliases": udp_cid_aliases,
            },
        }));
    }

    serde_json::json!({ "profiles": out })
}
async fn dispatch(req: Request, state: &Arc<ServerState>) -> Response {
    // Audit-log every administrative (state-changing) control command. list-clients
    // is read-only and may be polled, so it is excluded to avoid log spam.
    if req.cmd != "list-clients"
        && req.cmd != "list-blocked"
        && req.cmd != "roaming-stats"
        && req.cmd != "queue-stats"
        && req.cmd != "tun-stats"
    {
        log::info!(
            "CONTROL action='{}' user='{}' profile='{}' mbps={} ip='{}'",
            crate::util::log_sanitize(&req.cmd),
            crate::util::log_identity(&req.username),
            crate::util::log_sanitize(&req.profile),
            req.mbps,
            crate::util::log_sanitize(&req.ip)
        );
    }
    match req.cmd.as_str() {
        "list-clients" => {
            let profiles = state.profiles.read().await;
            let mut clients = Vec::new();
            for (pname, profile) in profiles.iter() {
                let sessions = profile.sessions.read().await;
                for s in sessions.by_ip.values() {
                    let reported = s.reported_client();
                    clients.push(ClientInfo {
                        profile: pname.clone(),
                        username: s.username.clone(),
                        ip: s.client_ip.to_string(),
                        addresses: s
                            .assigned_addresses()
                            .map(|address| address.to_string())
                            .collect(),
                        peer: s.peer.to_string(),
                        connected_secs: s.connected_at.elapsed().as_secs(),
                        bytes_sent: s.bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
                        bytes_recv: s.bytes_recv.load(std::sync::atomic::Ordering::Relaxed),
                        dropped: s.dropped.load(std::sync::atomic::Ordering::Relaxed),
                        bandwidth_limit_mbps: s
                            .bandwidth_limit_mbps
                            .load(std::sync::atomic::Ordering::Relaxed),
                        streams: s.stream_count() as u32,
                        client_version: reported.as_ref().map(|(v, _)| v.clone()),
                        client_platform: reported.map(|(_, p)| p),
                    });
                }
            }
            Response {
                ok: true,
                error: None,
                clients: Some(clients),
                message: None,
            }
        }

        "tun-stats" => {
            let profiles = state.profiles.read().await;
            let counters: std::collections::BTreeMap<_, _> = profiles
                .iter()
                .map(|(name, p)| (name.clone(), p.tun_metrics.snapshot()))
                .collect();
            Response {
                ok: true,
                error: None,
                clients: None,
                message: Some(
                    serde_json::json!({"scope":"server_tun_pipeline","profiles":counters})
                        .to_string(),
                ),
            }
        }
        "queue-stats" => {
            let profiles = state.profiles.read().await;
            let fragmentation: std::collections::BTreeMap<_, _> = profiles.iter().map(|(name, profile)| {
                let snapshot = profile.udp_buffer_counters.path.snapshot();
                (name.clone(), serde_json::json!({"fragmented_records":snapshot.fragmented_records,"fragments_created":snapshot.fragments_created}))
            }).collect();
            let queues: std::collections::BTreeMap<_, _> = profiles
                .iter()
                .map(|(name, profile)| {
                    (
                        name.clone(),
                        profile.udp_buffer_counters.receive_queue.snapshot(),
                    )
                })
                .collect();
            Response {
                ok: true,
                error: None,
                clients: None,
                message: Some(
                    serde_json::json!({"profiles": queues, "scope": "udp_batch_handoff", "data_fragmentation": fragmentation})
                        .to_string(),
                ),
            }
        }

        "roaming-stats" => Response {
            ok: true,
            error: None,
            clients: None,
            message: Some(roaming_status(state).await.to_string()),
        },
        "kick" => {
            if req.username.is_empty() {
                return Response {
                    ok: false,
                    error: Some("username required".into()),
                    clients: None,
                    message: None,
                };
            }
            let target_profiles: Vec<Arc<ProfileRuntime>> = {
                let profiles = state.profiles.read().await;
                if req.profile.is_empty() {
                    profiles.values().cloned().collect()
                } else {
                    match profiles.get(&req.profile) {
                        Some(p) => vec![p.clone()],
                        None => {
                            return Response {
                                ok: false,
                                error: Some(format!("profile '{}' not found", req.profile)),
                                clients: None,
                                message: None,
                            }
                        }
                    }
                }
            };
            let mut total_kicked = 0;
            for profile in &target_profiles {
                total_kicked += kick_user_on_profile(profile, &req.username).await;
            }

            if total_kicked == 0 {
                Response {
                    ok: false,
                    error: Some(format!("user '{}' not connected", req.username)),
                    clients: None,
                    message: None,
                }
            } else {
                Response {
                    ok: true,
                    error: None,
                    clients: None,
                    message: Some(format!(
                        "kicked {} ({} session(s))",
                        req.username, total_kicked
                    )),
                }
            }
        }

        "disable-user" => {
            if req.username.is_empty() {
                return Response {
                    ok: false,
                    error: Some("username required".into()),
                    clients: None,
                    message: None,
                };
            }

            // Re-read under the lock and apply the change there: this worker's copy may
            // be older than the file (the supervisor/CLI also write it).
            let (disabled, save_err) = {
                let auth_config = state.live_auth_config.read().await;
                let mut config = state.config.clone();
                config.auth = auth_config.clone();
                let users_file = config.auth.users_file.clone();
                let mut users = state.users_db.write().await;
                match UsersDb::update_locked_checked(&users_file, |db| {
                    let found = match external_or_inline_user(db, &config, &req.username) {
                        Some(u) => {
                            u.enabled = false;
                            true
                        }
                        None => false,
                    };
                    let effective =
                        crate::server::effective_users_from_external(&config, db.clone())?;
                    Ok((found, effective))
                }) {
                    Ok((_fresh, (found, effective))) => {
                        *users = effective;
                        (found, None)
                    }
                    Err(e) => {
                        log::error!("Failed to save users file after disable: {}", e);
                        (true, Some(users_write_failure(&config, &mut users, &e)))
                    }
                }
            };

            if !disabled {
                return Response {
                    ok: false,
                    error: Some(format!("user '{}' not found in users file", req.username)),
                    clients: None,
                    message: None,
                };
            }

            // Kick from all profiles (authoritative removal — see kick_user_on_profile).
            let target_profiles: Vec<Arc<ProfileRuntime>> =
                state.profiles.read().await.values().cloned().collect();
            let mut total_kicked = 0;
            for profile in &target_profiles {
                total_kicked += kick_user_on_profile(profile, &req.username).await;
            }

            match save_err {
                Some(e) => Response {
                    ok: false,
                    error: Some(format!(
                        "disable update for '{}' could not be confirmed; {} current session(s) were kicked ({})",
                        req.username, total_kicked, e
                    )),
                    clients: None,
                    message: None,
                },
                None => Response {
                    ok: true,
                    error: None,
                    clients: None,
                    message: Some(format!(
                        "user '{}' disabled — {} session(s) kicked",
                        req.username, total_kicked
                    )),
                },
            }
        }

        "set-limit" => {
            if req.username.is_empty() {
                return Response {
                    ok: false,
                    error: Some("username required".into()),
                    clients: None,
                    message: None,
                };
            }
            let (found, save_err) = {
                let auth_config = state.live_auth_config.read().await;
                let mut config = state.config.clone();
                config.auth = auth_config.clone();
                let users_file = config.auth.users_file.clone();
                let mut users = state.users_db.write().await;
                match UsersDb::update_locked_checked(&users_file, |db| {
                    let found = match external_or_inline_user(db, &config, &req.username) {
                        Some(u) => {
                            u.data_limit_gb = req.data_limit_gb;
                            u.expire_at = req.expire_at;
                            true
                        }
                        None => false,
                    };
                    let effective =
                        crate::server::effective_users_from_external(&config, db.clone())?;
                    Ok((found, effective))
                }) {
                    Ok((_fresh, (found, effective))) => {
                        *users = effective;
                        (found, None)
                    }
                    Err(e) => {
                        log::error!("Failed to save users file after set-limit: {}", e);
                        (true, Some(users_write_failure(&config, &mut users, &e)))
                    }
                }
            };
            if !found {
                return Response {
                    ok: false,
                    error: Some(format!("user '{}' not found in users file", req.username)),
                    clients: None,
                    message: None,
                };
            }
            match save_err {
                Some(e) => Response {
                    ok: false,
                    error: Some(format!("limit update could not be confirmed ({})", e)),
                    clients: None,
                    message: None,
                },
                None => Response {
                    ok: true,
                    error: None,
                    clients: None,
                    message: Some(format!(
                        "data cap for '{}' set to {} GB",
                        req.username, req.data_limit_gb
                    )),
                },
            }
        }

        "reset-usage" => {
            if req.username.is_empty() {
                return Response {
                    ok: false,
                    error: Some("username required".into()),
                    clients: None,
                    message: None,
                };
            }
            match state
                .usage
                .reset_and_flush_async(req.username.clone())
                .await
            {
                Ok(()) => Response {
                    ok: true,
                    error: None,
                    clients: None,
                    message: Some(format!("usage counter reset for '{}'", req.username)),
                },
                Err(error) => Response {
                    ok: false,
                    error: Some(usage_reset_failure(&error)),
                    clients: None,
                    message: None,
                },
            }
        }

        "enable-user" => {
            if req.username.is_empty() {
                return Response {
                    ok: false,
                    error: Some("username required".into()),
                    clients: None,
                    message: None,
                };
            }
            let auth_config = state.live_auth_config.read().await;
            let mut config = state.config.clone();
            config.auth = auth_config.clone();
            let users_file = config.auth.users_file.clone();
            let mut users = state.users_db.write().await;
            let outcome = UsersDb::update_locked_checked(&users_file, |db| {
                let found = match external_or_inline_user(db, &config, &req.username) {
                    Some(u) => {
                        u.enabled = true;
                        true
                    }
                    None => false,
                };
                let effective = crate::server::effective_users_from_external(&config, db.clone())?;
                Ok((found, effective))
            });
            let found = match &outcome {
                Ok((_fresh, (found, effective))) => {
                    *users = effective.clone();
                    *found
                }
                Err(_) => true, // report the save failure, not "no such user"
            };
            if found {
                match outcome {
                    Ok(_) => Response {
                        ok: true,
                        error: None,
                        clients: None,
                        message: Some(format!("user '{}' enabled", req.username)),
                    },
                    Err(e) => {
                        log::error!("Failed to save users file after enable: {}", e);
                        Response {
                            ok: false,
                            error: Some(format!(
                                "enable update for '{}' could not be confirmed ({})",
                                req.username,
                                users_write_failure(&config, &mut users, &e)
                            )),
                            clients: None,
                            message: None,
                        }
                    }
                }
            } else {
                Response {
                    ok: false,
                    error: Some(format!("user '{}' not found", req.username)),
                    clients: None,
                    message: None,
                }
            }
        }

        "set-bandwidth" => {
            if req.username.is_empty() {
                return Response {
                    ok: false,
                    error: Some("username required".into()),
                    clients: None,
                    message: None,
                };
            }
            let profiles = state.profiles.read().await;
            let target_profiles: Vec<&Arc<ProfileRuntime>> = if req.profile.is_empty() {
                profiles.values().collect()
            } else {
                match profiles.get(&req.profile) {
                    Some(p) => vec![p],
                    None => {
                        return Response {
                            ok: false,
                            error: Some(format!("profile '{}' not found", req.profile)),
                            clients: None,
                            message: None,
                        }
                    }
                }
            };
            for profile in target_profiles {
                let sessions = profile.sessions.read().await;
                for s in sessions
                    .by_ip
                    .values()
                    .filter(|s| s.username == req.username)
                {
                    s.bandwidth_limit_mbps
                        .store(req.mbps, std::sync::atomic::Ordering::Relaxed);
                }
            }
            drop(profiles);

            let (found, save_err) = {
                let auth_config = state.live_auth_config.read().await;
                let mut config = state.config.clone();
                config.auth = auth_config.clone();
                let users_file = config.auth.users_file.clone();
                let mut users = state.users_db.write().await;
                match UsersDb::update_locked_checked(&users_file, |db| {
                    let found = match external_or_inline_user(db, &config, &req.username) {
                        Some(user) => {
                            user.bandwidth.limit_mbps = req.mbps;
                            user.bandwidth.burst_mbps = req.mbps.saturating_add(req.mbps / 4);
                            true
                        }
                        None => false,
                    };
                    let effective =
                        crate::server::effective_users_from_external(&config, db.clone())?;
                    Ok((found, effective))
                }) {
                    Ok((_fresh, (found, effective))) => {
                        *users = effective;
                        (found, None)
                    }
                    Err(e) => {
                        log::error!("Failed to save users file after set-bandwidth: {}", e);
                        (true, Some(users_write_failure(&config, &mut users, &e)))
                    }
                }
            };

            if !found {
                return Response {
                    ok: false,
                    error: Some(format!("user '{}' not found", req.username)),
                    clients: None,
                    message: None,
                };
            }

            match save_err {
                Some(e) => Response {
                    ok: false,
                    error: Some(format!(
                        "bandwidth for {} set to {} Mbps on live session(s); users file update could not be confirmed ({})",
                        req.username, req.mbps, e
                    )),
                    clients: None,
                    message: None,
                },
                None => Response {
                    ok: true,
                    error: None,
                    clients: None,
                    message: Some(format!(
                        "bandwidth for {} set to {} Mbps",
                        req.username, req.mbps
                    )),
                },
            }
        }

        "show-routes" => {
            if req.username.is_empty() {
                return Response {
                    ok: false,
                    error: Some("username required".into()),
                    clients: None,
                    message: None,
                };
            }
            let users = state.users_db.read().await;
            match users.find_user(&req.username) {
                Some(user) if !user.routes.is_empty() => {
                    let routes: Vec<String> = user
                        .routes
                        .iter()
                        .map(|r| {
                            format!(
                                "{} via {} metric {}",
                                r.cidr,
                                // An omitted gateway resolves to the tun.address of whichever
                                // profile the user connects on (build_routes_json_for_user), and
                                // a user may span profiles — so name that rule rather than print
                                // one profile's address as if it were the answer.
                                r.gateway.as_deref().unwrap_or("<profile tun.address>"),
                                r.metric.unwrap_or(100)
                            )
                        })
                        .collect();
                    Response {
                        ok: true,
                        error: None,
                        clients: None,
                        message: Some(routes.join("; ")),
                    }
                }
                Some(_) => Response {
                    ok: true,
                    error: None,
                    clients: None,
                    message: Some("using global advertised_routes".into()),
                },
                None => Response {
                    ok: false,
                    error: Some(format!("user '{}' not found", req.username)),
                    clients: None,
                    message: None,
                },
            }
        }

        "list-blocked" => {
            let mut list: Vec<BlockedInfo> = {
                let tracker = state.failed_auth.lock().await;
                tracker
                    .list_blocked_ips()
                    .into_iter()
                    .map(|(ip, failures, secs)| BlockedInfo {
                        ip: ip.to_string(),
                        failures,
                        unblock_in_secs: secs,
                    })
                    .collect()
            };
            list.sort_by(|a, b| a.ip.cmp(&b.ip));
            let json = serde_json::to_string(&list).unwrap_or_else(|_| "[]".into());
            Response {
                ok: true,
                error: None,
                clients: None,
                message: Some(json),
            }
        }
        "unblock" => match req.ip.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                let removed = state.failed_auth.lock().await.unblock_ip(ip);
                if removed {
                    Response {
                        ok: true,
                        error: None,
                        clients: None,
                        message: Some(format!("IP {} unblocked", ip)),
                    }
                } else {
                    Response {
                        ok: false,
                        error: Some(format!("IP {} was not blocked", ip)),
                        clients: None,
                        message: None,
                    }
                }
            }
            Err(_) => Response {
                ok: false,
                error: Some(format!(
                    "'{}' is not a valid IP address",
                    crate::util::log_sanitize(&req.ip)
                )),
                clients: None,
                message: None,
            },
        },
        "unblock-all" => {
            let n = state.failed_auth.lock().await.clear_all_ips();
            Response {
                ok: true,
                error: None,
                clients: None,
                message: Some(format!("cleared {} blocked/penalized IP(s)", n)),
            }
        }

        cmd => Response {
            ok: false,
            error: Some(format!("unknown command: {}", cmd)),
            clients: None,
            message: None,
        },
    }
}

pub async fn send_command(socket_path: &str, cmd_json: &str) -> anyhow::Result<String> {
    let mut stream = tokio::time::timeout(IO_TIMEOUT, tokio::net::UnixStream::connect(socket_path))
        .await
        .map_err(|_| anyhow::anyhow!("Timed out connecting to control socket {socket_path}"))?
        .map_err(|error| {
            anyhow::anyhow!(
                "Cannot connect to control socket {socket_path}: {error}\nIs the server running?"
            )
        })?;
    control_io::write_line(&mut stream, cmd_json, MAX_REQUEST, IO_TIMEOUT).await?;
    let response = control_io::read_line(&mut stream, MAX_RESPONSE, RESPONSE_TIMEOUT)
        .await
        .map_err(|error| anyhow::anyhow!("Cannot read control reply from {socket_path}: {error}"))?
        .ok_or_else(|| anyhow::anyhow!("Control socket {socket_path} closed without a reply"))?;
    Ok(response.trim().to_string())
}

#[cfg(test)]
mod tests {
    //! Coverage for the control channel's input layer (audit 7.1). The dispatcher
    //! itself needs a full ServerState to exercise, but the security-relevant edge —
    //! parsing an untrusted command off the socket without panicking on malformed /
    //! unknown / wrong-typed input — is unit-testable and is what these lock in.
    use super::*;

    #[test]
    fn reset_failure_message_distinguishes_publication_from_rollback() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-reset-message-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("usage.json");
        let error = crate::util::write_atomic_test_sync_failure(&path, b"{}")
            .unwrap_err()
            .context("usage reset");
        let message = usage_reset_failure(&error);
        assert!(message.contains("was published"));
        assert!(message.contains("durability could not be confirmed"));
        assert!(message.contains("injected directory I/O failure"));
        assert!(!message.contains("was not reset"));
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        let before = usage_reset_failure(&anyhow::anyhow!("preparation failed"));
        assert!(before.contains("was not reset"));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    fn parse(json: &str) -> Result<Request, serde_json::Error> {
        serde_json::from_str::<Request>(json)
    }

    #[test]
    fn runtime_mutation_materializes_and_keeps_an_inline_user_override() {
        let mut config = crate::config::server::ServerConfig::default();
        config.auth.users.push(crate::config::users::UserEntry {
            username: "inline-alice".to_string(),
            password_hash: "hash".to_string(),
            enabled: true,
            ..Default::default()
        });
        let mut external = UsersDb::default();

        let user = external_or_inline_user(&mut external, &config, "inline-alice")
            .expect("inline user must be materialized as a file override");
        user.enabled = false;
        let effective = crate::server::effective_users_from_external(&config, external)
            .expect("override union must remain valid");

        assert_eq!(effective.users.len(), 1);
        assert_eq!(effective.users[0].username, "inline-alice");
        assert!(
            !effective.users[0].enabled,
            "external override must keep precedence over the inline entry"
        );
    }

    #[tokio::test]
    async fn control_mutations_use_accepted_inline_auth_instead_of_startup_users() {
        use crate::config::users::UserEntry;
        let dir = std::env::temp_dir().join(format!(
            "qeli-control-live-inline-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let users_file = dir.join("users.conf");
        std::fs::write(&users_file, "").unwrap();
        let mut config = crate::config::server::ServerConfig::default();
        config.auth.users_file = users_file.to_string_lossy().into_owned();
        config.auth.users.push(UserEntry {
            username: "removed-inline".into(),
            password_hash: "x".into(),
            enabled: true,
            ..Default::default()
        });
        let state = crate::server::test_api_state(config, &dir.join("server.conf"));
        let new_user = UserEntry {
            username: "new-inline".into(),
            password_hash: "y".into(),
            enabled: true,
            ..Default::default()
        };
        state.live_auth_config.write().await.users = vec![new_user.clone()];
        state.users_db.write().await.users = vec![new_user];
        for cmd in ["enable-user", "disable-user", "set-limit", "set-bandwidth"] {
            let request = parse(&format!(
                r#"{{"cmd":"{cmd}","username":"removed-inline","mbps":7,"data_limit_gb":9}}"#
            ))
            .unwrap();
            assert!(
                !dispatch(request, &state).await.ok,
                "{cmd} resurrected an account"
            );
            assert!(!UsersDb::load(&users_file)
                .unwrap()
                .users
                .iter()
                .any(|u| u.username == "removed-inline"));
            let request = parse(&format!(
                r#"{{"cmd":"{cmd}","username":"new-inline","mbps":7,"data_limit_gb":9}}"#
            ))
            .unwrap();
            assert!(
                dispatch(request, &state).await.ok,
                "{cmd} ignored the accepted inline account"
            );
        }
        let db = UsersDb::load(&users_file).unwrap();
        let user = &db.users[0];
        assert_eq!(user.username, "new-inline");
        assert!(!user.enabled);
        assert_eq!(user.data_limit_gb, 9);
        assert_eq!(user.bandwidth.limit_mbps, 7);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn full_command_parses_all_fields() {
        let r = parse(
            r#"{"cmd":"set-limit","username":"alice","profile":"tcp","mbps":50,
                "data_limit_gb":100,"expire_at":1234567890,"ip":"1.2.3.4"}"#,
        )
        .unwrap();
        assert_eq!(r.cmd, "set-limit");
        assert_eq!(r.username, "alice");
        assert_eq!(r.profile, "tcp");
        assert_eq!(r.mbps, 50);
        assert_eq!(r.data_limit_gb, 100);
        assert_eq!(r.expire_at, Some(1234567890));
        assert_eq!(r.ip, "1.2.3.4");
    }

    #[test]
    fn minimal_command_applies_defaults() {
        // Only `cmd` is required; every other field is #[serde(default)].
        let r = parse(r#"{"cmd":"list-clients"}"#).unwrap();
        assert_eq!(r.cmd, "list-clients");
        assert_eq!(r.username, "");
        assert_eq!(r.profile, "");
        assert_eq!(r.mbps, 0);
        assert_eq!(r.data_limit_gb, 0);
        assert_eq!(r.expire_at, None);
        assert_eq!(r.ip, "");
    }

    #[test]
    fn every_dispatch_verb_parses() {
        // The protocol must accept each verb the dispatcher handles (control.rs match).
        for cmd in [
            "list-clients",
            "list-blocked",
            "roaming-stats",
            "queue-stats",
            "tun-stats",
            "kick",
            "disable-user",
            "set-limit",
            "reset-usage",
            "enable-user",
            "set-bandwidth",
            "show-routes",
            "unblock",
            "unblock-all",
        ] {
            let r = parse(&format!(r#"{{"cmd":"{cmd}"}}"#))
                .unwrap_or_else(|e| panic!("verb {cmd:?} must parse: {e}"));
            assert_eq!(r.cmd, cmd);
        }
    }

    #[test]
    fn missing_cmd_is_an_error_not_a_panic() {
        assert!(parse(r#"{"username":"bob"}"#).is_err());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // No deny_unknown_fields — a newer client sending an extra field must not
        // break an older server (forward compatibility).
        let r = parse(r#"{"cmd":"kick","username":"x","future_field":true}"#).unwrap();
        assert_eq!(r.cmd, "kick");
        assert_eq!(r.username, "x");
    }

    #[test]
    fn malformed_and_wrong_typed_input_errors_cleanly() {
        assert!(parse(r#"{"cmd":"set-limit","mbps":"lots"}"#).is_err()); // mbps must be u32
        assert!(parse(r#"not json at all"#).is_err());
        assert!(parse(r#"{"cmd":123}"#).is_err()); // cmd must be a string
        assert!(parse(r#"{"cmd":"kick","mbps":-1}"#).is_err()); // u32 can't be negative
    }

    #[test]
    fn expire_at_accepts_null_and_negative() {
        assert_eq!(
            parse(r#"{"cmd":"disable-user","expire_at":null}"#)
                .unwrap()
                .expire_at,
            None
        );
        // A negative epoch parses (i64); the value layer, not the parser, judges it.
        assert_eq!(
            parse(r#"{"cmd":"disable-user","expire_at":-5}"#)
                .unwrap()
                .expire_at,
            Some(-5)
        );
    }

    #[test]
    fn response_omits_none_fields() {
        // skip_serializing_if keeps the wire minimal — an ok reply is just {"ok":true}.
        let r = Response {
            ok: true,
            error: None,
            clients: None,
            message: None,
        };
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"ok":true}"#);
    }

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let path = std::env::temp_dir().join(format!(
                "qeli-ctrl-test-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn socket(&self) -> std::path::PathBuf {
            self.0.join("control.sock")
        }
        fn state(&self) -> Arc<ServerState> {
            crate::server::test_api_state(
                crate::config::server::ServerConfig::default(),
                &self.0.join("server.conf"),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn control_shutdown_drains_accepted_mutation_and_holds_lease() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let state = fixture.state();
        let tracker_guard = state.failed_auth.lock().await;
        let mut owned = ControlSocket::bind(&path).unwrap();
        let listener = owned.listener.take().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handler_state = state.clone();
        let task = tokio::spawn(async move {
            let result = run_control_server(handler_state, listener, stop_rx).await;
            drop(owned);
            result
        });
        let mut peer = tokio::net::UnixStream::connect(&path).await.unwrap();
        control_io::write_line(
            &mut peer,
            r#"{"cmd":"unblock-all"}"#,
            MAX_REQUEST,
            IO_TIMEOUT,
        )
        .await
        .unwrap();
        tokio::time::timeout(IO_TIMEOUT, async {
            while Arc::strong_count(&state) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop_tx.send(true).unwrap();
        // The handler cannot complete while its mutation lock is held.
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert!(ControlSocket::bind(&path).is_err());
        drop(tracker_guard);
        let response = control_io::read_line(&mut peer, MAX_RESPONSE, IO_TIMEOUT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response).unwrap()["ok"],
            true
        );
        tokio::time::timeout(IO_TIMEOUT, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(Arc::strong_count(&state), 1);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn control_shutdown_at_capacity_joins_all_handlers() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let state = fixture.state();
        let mut owned = ControlSocket::bind(&path).unwrap();
        let listener = owned.listener.take().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handler_state = state.clone();
        let task = tokio::spawn(async move {
            let result = run_control_server(handler_state, listener, stop_rx).await;
            drop(owned);
            result
        });
        let mut peers = Vec::new();
        for _ in 0..16 {
            peers.push(tokio::net::UnixStream::connect(&path).await.unwrap());
        }
        tokio::time::timeout(IO_TIMEOUT, async {
            while Arc::strong_count(&state) < 18 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop_tx.send(true).unwrap();
        drop(peers);
        tokio::time::timeout(IO_TIMEOUT, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(Arc::strong_count(&state), 1);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn control_closed_owner_stops_before_accepting() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let mut owned = ControlSocket::bind(&path).unwrap();
        let listener = owned.listener.take().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        drop(stop_tx);
        tokio::time::timeout(
            IO_TIMEOUT,
            run_control_server(fixture.state(), listener, stop_rx),
        )
        .await
        .unwrap()
        .unwrap();
        drop(owned);
        assert!(!path.exists());
    }
}
