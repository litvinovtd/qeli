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
    pub bandwidth_limit_mbps: u32,
}

pub async fn run_control_server(state: Arc<ServerState>) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(CONTROL_SOCKET).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::remove_file(CONTROL_SOCKET).ok();

    let listener = UnixListener::bind(CONTROL_SOCKET)?;
    #[cfg(unix)]
    std::fs::set_permissions(
        CONTROL_SOCKET,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;

    log::info!("Control socket listening on {}", CONTROL_SOCKET);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::debug!("Control accept error: {}", e);
                continue;
            }
        };

        let state = state.clone();
        tokio::spawn(async move {
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

    let line = match lines.next_line().await? {
        Some(l) => l,
        None => return Ok(()),
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

async fn dispatch(req: Request, state: &Arc<ServerState>) -> Response {
    // Audit-log every administrative (state-changing) control command. list-clients
    // is read-only and may be polled, so it is excluded to avoid log spam.
    if req.cmd != "list-clients" {
        log::info!(
            "CONTROL action='{}' user='{}' profile='{}' mbps={}",
            req.cmd,
            req.username,
            req.profile,
            req.mbps
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
                        bandwidth_limit_mbps: s
                            .bandwidth_limit_mbps
                            .load(std::sync::atomic::Ordering::Relaxed),
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
            let mut total_kicked = 0;
            for profile in target_profiles {
                let sessions = profile.sessions.read().await;
                let to_kick: Vec<_> = sessions
                    .by_ip
                    .values()
                    .filter(|s| s.username == req.username)
                    .cloned()
                    .collect();
                let kicked_count = to_kick.len();
                drop(sessions);
                for s in to_kick {
                    s.kick_all();
                }
                total_kicked += kicked_count;
            }
            drop(profiles);

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

            let disabled = {
                let mut users = state.users_db.write().await;
                let found = users.users.iter_mut().find(|u| u.username == req.username);
                if let Some(u) = found {
                    u.enabled = false;
                    let users_file = state.config.auth.users_file.clone();
                    if let Err(e) = users.save(&users_file) {
                        log::error!("Failed to save users file after disable: {}", e);
                    }
                    true
                } else {
                    false
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

            // Kick from all profiles
            let profiles = state.profiles.read().await;
            let mut total_kicked = 0;
            for (_, profile) in profiles.iter() {
                let sessions = profile.sessions.read().await;
                let to_kick: Vec<_> = sessions
                    .by_ip
                    .values()
                    .filter(|s| s.username == req.username)
                    .cloned()
                    .collect();
                drop(sessions);
                let n = to_kick.len();
                for s in to_kick {
                    s.kick_all();
                }
                total_kicked += n;
            }

            Response {
                ok: true,
                error: None,
                clients: None,
                message: Some(format!(
                    "user '{}' disabled — {} session(s) kicked",
                    req.username, total_kicked
                )),
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
                if let Err(e) = users.save(&users_file) {
                    log::error!("Failed to save users file after enable: {}", e);
                }
                Response {
                    ok: true,
                    error: None,
                    clients: None,
                    message: Some(format!("user '{}' enabled", req.username)),
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

            {
                let mut users = state.users_db.write().await;
                if users.set_bandwidth(&req.username, req.mbps) {
                    let users_file = state.config.auth.users_file.clone();
                    if let Err(e) = users.save(&users_file) {
                        log::error!("Failed to save users file after set-bandwidth: {}", e);
                    }
                }
            }

            Response {
                ok: true,
                error: None,
                clients: None,
                message: Some(format!(
                    "bandwidth for {} set to {} Mbps",
                    req.username, req.mbps
                )),
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
