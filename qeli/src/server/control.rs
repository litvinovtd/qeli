use crate::server::{ProfileRuntime, ServerState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

pub const CONTROL_SOCKET: &str = "/var/run/qeli/control.sock";

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
    pub ip: String,
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
}

pub async fn run_control_server(state: Arc<ServerState>) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(CONTROL_SOCKET).parent() {
        std::fs::create_dir_all(parent).ok();
        // Lock the socket's directory to 0700 BEFORE binding, so that during the
        // unavoidable window between bind() (which creates the socket with the
        // process umask, typically world-traversable) and the 0600 chmod below,
        // the socket is still unreachable by other users — the directory gates
        // traversal. (L2)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    std::fs::remove_file(CONTROL_SOCKET).ok();

    let listener = UnixListener::bind(CONTROL_SOCKET)?;
    #[cfg(unix)]
    std::fs::set_permissions(
        CONTROL_SOCKET,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;

    log::info!("Control socket listening on {}", CONTROL_SOCKET);

    // Bound concurrent control handlers: acquire a permit BEFORE accepting the
    // next connection, so a flood of connections queues in the kernel backlog
    // instead of spawning unbounded tasks/fds (each handler also has a read
    // timeout below, so a silent peer can't park a slot forever).
    let sem = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break Ok(()), // semaphore closed — shouldn't happen
        };
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::debug!("Control accept error: {}", e);
                continue; // permit released here
            }
        };

        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the handler's lifetime
            if let Err(e) = handle_control(stream, state).await {
                log::debug!("Control handler error: {}", e);
            }
        });
    }
}

async fn handle_control(
    mut stream: tokio::net::UnixStream,
    state: Arc<ServerState>,
) -> anyhow::Result<()> {
    // Cap the request size: a control command is a single short JSON line.
    // Without a bound, a client holding the socket open and streaming bytes
    // without a newline would grow the line buffer unboundedly (OOM). 64 KiB is
    // far more than any legitimate command needs.
    const MAX_CONTROL_REQUEST: u64 = 64 * 1024;
    let (reader, mut writer) = stream.split();
    let mut lines =
        BufReader::new(tokio::io::AsyncReadExt::take(reader, MAX_CONTROL_REQUEST)).lines();

    // Read timeout: a peer that connects and never sends a newline must not park
    // this task + fd indefinitely (the 64 KiB `take` bounds memory, not time).
    let line =
        match tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line()).await {
            Ok(Ok(Some(l))) => l,
            Ok(Ok(None)) => return Ok(()), // clean EOF, no command
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()), // timed out waiting for a command line
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

    let mut out = serde_json::to_string(&resp)?;
    out.push('\n');
    writer.write_all(out.as_bytes()).await?;
    Ok(())
}

#[allow(dead_code)] // profile lookup helper kept for control-command handlers
fn find_profile<'a>(
    profiles: &'a HashMap<String, Arc<ProfileRuntime>>,
    name: &str,
) -> Option<&'a Arc<ProfileRuntime>> {
    if name.is_empty() {
        // Default to first profile
        profiles.values().next()
    } else {
        profiles.get(name)
    }
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
    let kicked = {
        let mut sessions = profile.sessions.write().await;
        let ips: Vec<std::net::Ipv4Addr> = sessions
            .by_ip
            .iter()
            .filter(|(_, s)| s.username == username)
            .map(|(ip, _)| *ip)
            .collect();
        let mut out = Vec::with_capacity(ips.len());
        for ip in ips {
            if let Some(s) = sessions.by_ip.remove(&ip) {
                sessions.by_token.remove(&s.token);
                out.push(s);
            }
        }
        out
    };
    for s in &kicked {
        s.kick_all();
        profile.pool.lock().await.release(&s.device_key);
    }
    kicked.len()
}

async fn dispatch(req: Request, state: &Arc<ServerState>) -> Response {
    // Audit-log every administrative (state-changing) control command. list-clients
    // is read-only and may be polled, so it is excluded to avoid log spam.
    if req.cmd != "list-clients" && req.cmd != "list-blocked" {
        log::info!(
            "CONTROL action='{}' user='{}' profile='{}' mbps={} ip='{}'",
            crate::util::log_sanitize(&req.cmd),
            crate::util::log_sanitize(&req.username),
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
                    clients.push(ClientInfo {
                        profile: pname.clone(),
                        username: s.username.clone(),
                        ip: s.client_ip.to_string(),
                        peer: s.peer.to_string(),
                        connected_secs: s.connected_at.elapsed().as_secs(),
                        bytes_sent: s.bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
                        bytes_recv: s.bytes_recv.load(std::sync::atomic::Ordering::Relaxed),
                        dropped: s.dropped.load(std::sync::atomic::Ordering::Relaxed),
                        bandwidth_limit_mbps: s
                            .bandwidth_limit_mbps
                            .load(std::sync::atomic::Ordering::Relaxed),
                        streams: s.stream_count() as u32,
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

            let (disabled, save_err) = {
                let mut users = state.users_db.write().await;
                let found = users.users.iter_mut().find(|u| u.username == req.username);
                if let Some(u) = found {
                    u.enabled = false;
                    let users_file = state.config.auth.users_file.clone();
                    let save_err = users.save(&users_file).err().map(|e| {
                        log::error!("Failed to save users file after disable: {}", e);
                        e.to_string()
                    });
                    (true, save_err)
                } else {
                    (false, None)
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
                        "user '{}' disabled in memory and {} session(s) kicked, but persisting \
                         to the users file FAILED ({}) — the change will be lost on restart",
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
                let mut users = state.users_db.write().await;
                if let Some(u) = users.users.iter_mut().find(|u| u.username == req.username) {
                    u.data_limit_gb = req.data_limit_gb;
                    u.expire_at = req.expire_at;
                    let users_file = state.config.auth.users_file.clone();
                    let e = users.save(&users_file).err().map(|e| {
                        log::error!("Failed to save users file after set-limit: {}", e);
                        e.to_string()
                    });
                    (true, e)
                } else {
                    (false, None)
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
                    error: Some(format!(
                        "limit set in memory but persisting to the users file FAILED ({}) — \
                         it will be lost on restart",
                        e
                    )),
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
            state.usage.reset(&req.username);
            state.usage.flush();
            Response {
                ok: true,
                error: None,
                clients: None,
                message: Some(format!("usage counter reset for '{}'", req.username)),
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
            let mut users = state.users_db.write().await;
            let found = users.users.iter_mut().find(|u| u.username == req.username);
            if let Some(u) = found {
                u.enabled = true;
                let users_file = state.config.auth.users_file.clone();
                match users.save(&users_file) {
                    Ok(()) => Response {
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
                                "user '{}' enabled in memory, but persisting to the users file \
                                 FAILED ({}) — the change will be lost on restart",
                                req.username, e
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

            let save_err = {
                let mut users = state.users_db.write().await;
                if users.set_bandwidth(&req.username, req.mbps) {
                    let users_file = state.config.auth.users_file.clone();
                    users.save(&users_file).err().map(|e| {
                        log::error!("Failed to save users file after set-bandwidth: {}", e);
                        e.to_string()
                    })
                } else {
                    None
                }
            };

            match save_err {
                Some(e) => Response {
                    ok: false,
                    error: Some(format!(
                        "bandwidth for {} set to {} Mbps on live session(s), but persisting to \
                         the users file FAILED ({}) — the change will be lost on restart",
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
                                r.gateway.as_deref().unwrap_or("10.0.0.1"),
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
    use tokio::io::AsyncReadExt;
    let mut stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Cannot connect to control socket {}: {}\nIs the server running?",
                socket_path,
                e
            )
        })?;

    let mut msg = cmd_json.to_string();
    msg.push('\n');
    stream.write_all(msg.as_bytes()).await?;

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await?;
    Ok(resp.trim().to_string())
}

#[cfg(test)]
mod tests {
    //! Coverage for the control channel's input layer (audit 7.1). The dispatcher
    //! itself needs a full ServerState to exercise, but the security-relevant edge —
    //! parsing an untrusted command off the socket without panicking on malformed /
    //! unknown / wrong-typed input — is unit-testable and is what these lock in.
    use super::*;

    fn parse(json: &str) -> Result<Request, serde_json::Error> {
        serde_json::from_str::<Request>(json)
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
    fn find_profile_on_empty_map_is_none() {
        let empty: HashMap<String, Arc<ProfileRuntime>> = HashMap::new();
        assert!(find_profile(&empty, "").is_none());
        assert!(find_profile(&empty, "anything").is_none());
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
}
