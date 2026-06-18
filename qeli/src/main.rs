// Modules live in the library crate (`src/lib.rs`) so the realtls FFI can be
// cross-compiled as a cdylib for Android/Windows. The binary only drives the CLI
// (server/client), which is Linux-only — build the cdylib with `--lib`.
use qeli::config;
#[cfg(target_os = "linux")]
use qeli::{client, server};

#[cfg(not(target_os = "linux"))]
compile_error!("the qeli *binary* is Linux-only (the realtls FFI library is cross-platform)");

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "qeli", about = "Obfuscated VPN with custom protocol", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in server mode
    Server {
        #[arg(short, long, default_value = "/etc/qeli/server.conf")]
        config: PathBuf,
    },
    /// Internal: the data-plane worker child spawned by `server`. Not for direct
    /// use — `server` is the supervisor that manages it.
    #[command(name = "_worker", hide = true)]
    Worker {
        #[arg(short, long, default_value = "/etc/qeli/server.conf")]
        config: PathBuf,
    },
    /// Run in client mode
    Client {
        #[arg(short, long, default_value = "/etc/qeli/client.conf")]
        config: PathBuf,
    },
    /// List currently connected clients
    #[command(name = "list-clients")]
    ListClients {
        #[arg(long, default_value = "/var/run/qeli/control.sock")]
        socket: String,
    },
    /// Forcefully disconnect a user
    Kick {
        username: String,
        #[arg(long, default_value = "/var/run/qeli/control.sock")]
        socket: String,
    },
    /// Set bandwidth limit for a user (0 = unlimited)
    #[command(name = "set-bandwidth")]
    SetBandwidth {
        username: String,
        /// Bandwidth limit in Mbit/s (0 = unlimited)
        mbps: u32,
        #[arg(long, default_value = "/var/run/qeli/control.sock")]
        socket: String,
    },
    /// Show routes configured for a user
    #[command(name = "show-routes")]
    ShowRoutes {
        username: String,
        #[arg(long, default_value = "/var/run/qeli/control.sock")]
        socket: String,
    },
    /// Disable user permanently (kick + block reconnects)
    #[command(name = "disable-user")]
    DisableUser {
        username: String,
        #[arg(long, default_value = "/var/run/qeli/control.sock")]
        socket: String,
    },
    /// Re-enable a previously disabled user
    #[command(name = "enable-user")]
    EnableUser {
        username: String,
        #[arg(long, default_value = "/var/run/qeli/control.sock")]
        socket: String,
    },
    /// Show each profile's server identity public key (pin these on clients).
    /// Loads existing keys, or creates them if absent (same as server startup).
    #[command(name = "show-identity")]
    ShowIdentity {
        #[arg(short, long, default_value = "/etc/qeli/server.conf")]
        config: PathBuf,
    },
    /// Rotate (regenerate) one profile's server identity key. Clients of that
    /// profile must update auth.server_public_key afterwards.
    #[command(name = "rotate-identity")]
    RotateIdentity {
        /// Profile name whose identity key to regenerate
        profile: String,
        #[arg(short, long, default_value = "/etc/qeli/server.conf")]
        config: PathBuf,
    },
    /// Add a new client (user) to the users file. Hashes the password with
    /// Argon2 and appends the record; optionally prints a `qeli://` share link
    /// (a QR for it) so the client can be imported on a phone in one shot.
    #[command(name = "add-client")]
    AddClient {
        /// Username for the new client
        username: String,
        /// Password (plaintext). If omitted, a strong random one is generated
        /// and printed once — it cannot be recovered later (only the hash is stored).
        #[arg(short, long)]
        password: Option<String>,
        /// Restrict this client to these profiles (comma-separated). Empty = all profiles.
        #[arg(long)]
        profiles: Option<String>,
        /// Static tunnel IP for this client (optional).
        #[arg(long)]
        static_ip: Option<String>,
        /// Max concurrent sessions (0 = group/default).
        #[arg(long, default_value_t = 0)]
        max_sessions: u32,
        /// Also print a qeli:// share link for the given profile. Requires --host.
        #[arg(long)]
        link: bool,
        /// Profile to build the share link for (defaults to the first profile).
        #[arg(long)]
        link_profile: Option<String>,
        /// Server's public reachable address for the share link (host or host:port).
        #[arg(long)]
        host: Option<String>,
        #[arg(short, long, default_value = "/etc/qeli/server.conf")]
        config: PathBuf,
    },
    /// Set (or generate) the web admin-panel login in the server config — for a
    /// fresh install where you have no panel access yet. Writes web.username /
    /// web.password_hash (Argon2id, random salt) into the `[web]` section,
    /// preserving comments, and enables the panel. Restart qeli to apply.
    #[command(name = "set-web-password")]
    SetWebPassword {
        /// Admin username for the panel login.
        #[arg(long, default_value = "admin")]
        username: String,
        /// Password (plaintext). If omitted, a strong random one is generated and
        /// printed once — only the Argon2id hash is stored in the config.
        #[arg(short, long)]
        password: Option<String>,
        /// Only set credentials; do NOT flip web.enabled = true.
        #[arg(long)]
        no_enable: bool,
        #[arg(short, long, default_value = "/etc/qeli/server.conf")]
        config: PathBuf,
    },
}

/// Read just the `logging` section from a config file so the logger can be set
/// up before the rest of the config is parsed. Falls back to (info, stderr) on
/// any error — the real parse later will surface config problems.
fn peek_logging(path: &PathBuf) -> (String, Option<String>) {
    if let Ok(s) = std::fs::read_to_string(path) {
        // The only config format is flat INI: read its `[logging]` section.
        if let Ok(doc) = config::format::IniDoc::parse(&s) {
            if let Some(log) = doc.section("logging") {
                let level = log.get_or("level", "info").to_string();
                let file = log
                    .get("file")
                    .filter(|f| !f.is_empty())
                    .map(str::to_string);
                return (level, file);
            }
        }
    }
    ("info".to_string(), None)
}

/// Local-time timestamp in `YYYY-MM-DD HH:MM:SS:mmm` form (no `T`/`Z`).
#[cfg(target_os = "linux")]
fn log_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as libc::time_t;
    let millis = now.subsec_millis();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&secs, &mut tm);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}:{:03}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        millis
    )
}

/// Initialise env_logger at `level`, writing to `file` if given (creating its
/// parent directory), otherwise to stderr (captured by journald under systemd).
/// `RUST_LOG` still overrides the level when set.
fn init_logging(level: &str, file: Option<&str>) {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level));
    #[cfg(target_os = "linux")]
    builder.format(|buf, record| {
        use std::io::Write;
        writeln!(
            buf,
            "{} {:<5} {}: {}",
            log_timestamp(),
            record.level(),
            record.target(),
            record.args()
        )
    });
    if let Some(path) = file {
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(f) => {
                builder.target(env_logger::Target::Pipe(Box::new(f)));
            }
            Err(e) => eprintln!(
                "qeli: cannot open log file {}: {} — logging to stderr",
                path, e
            ),
        }
    }
    builder.init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Configure logging from the config's `logging` section (level + optional
    // file) so server/client logs land where the operator expects.
    let (level, log_file) = match &cli.command {
        Commands::Server { config } | Commands::Worker { config } | Commands::Client { config } => {
            peek_logging(config)
        }
        _ => ("info".to_string(), None),
    };
    init_logging(&level, log_file.as_deref());

    match cli.command {
        Commands::Server { config } => {
            log::info!(
                "Starting server (supervisor) with config: {}",
                config.display()
            );
            #[cfg(target_os = "linux")]
            {
                let config_str = config.to_str().ok_or_else(|| {
                    anyhow::anyhow!("config path is not valid UTF-8: {}", config.display())
                })?;
                server::run_supervisor(config_str).await?;
            }
        }

        Commands::Worker { config } => {
            log::info!(
                "Starting data-plane worker with config: {}",
                config.display()
            );
            #[cfg(target_os = "linux")]
            {
                let config_str = config.to_str().ok_or_else(|| {
                    anyhow::anyhow!("config path is not valid UTF-8: {}", config.display())
                })?;
                server::run_worker(config_str).await?;
            }
        }

        Commands::Client { config } => {
            log::info!("Starting client with config: {}", config.display());
            #[cfg(target_os = "linux")]
            {
                let config_str = config.to_str().ok_or_else(|| {
                    anyhow::anyhow!("config path is not valid UTF-8: {}", config.display())
                })?;
                client::run_client(config_str).await?;
            }
        }

        Commands::ListClients { socket } => {
            #[cfg(target_os = "linux")]
            {
                let resp =
                    server::control::send_command(&socket, r#"{"cmd":"list-clients"}"#).await?;
                print_list_clients(&resp)?;
            }
        }

        Commands::Kick { username, socket } => {
            #[cfg(target_os = "linux")]
            {
                // serde_json::json! безопасно экранирует username
                let cmd = serde_json::json!({"cmd": "kick", "username": username}).to_string();
                let resp = server::control::send_command(&socket, &cmd).await?;
                print_response(&resp);
            }
        }

        Commands::SetBandwidth {
            username,
            mbps,
            socket,
        } => {
            #[cfg(target_os = "linux")]
            {
                let cmd =
                    serde_json::json!({"cmd": "set-bandwidth", "username": username, "mbps": mbps})
                        .to_string();
                let resp = server::control::send_command(&socket, &cmd).await?;
                print_response(&resp);
            }
        }

        Commands::ShowRoutes { username, socket } => {
            #[cfg(target_os = "linux")]
            {
                let cmd =
                    serde_json::json!({"cmd": "show-routes", "username": username}).to_string();
                let resp = server::control::send_command(&socket, &cmd).await?;
                print_response(&resp);
            }
        }

        Commands::DisableUser { username, socket } => {
            #[cfg(target_os = "linux")]
            {
                let cmd =
                    serde_json::json!({"cmd": "disable-user", "username": username}).to_string();
                let resp = server::control::send_command(&socket, &cmd).await?;
                print_response(&resp);
            }
        }

        Commands::EnableUser { username, socket } => {
            #[cfg(target_os = "linux")]
            {
                let cmd =
                    serde_json::json!({"cmd": "enable-user", "username": username}).to_string();
                let resp = server::control::send_command(&socket, &cmd).await?;
                print_response(&resp);
            }
        }

        Commands::ShowIdentity { config } => {
            #[cfg(target_os = "linux")]
            {
                let s = std::fs::read_to_string(&config)?;
                let cfg: config::server::ServerConfig = config::parse_server_config(&s)?;
                println!(
                    "{:<14} {:<22} SERVER PUBLIC KEY (pin on client)",
                    "PROFILE", "BIND"
                );
                for p in &cfg.profiles {
                    let kp = server::load_or_generate_profile_key(p)?;
                    let hex: String = kp
                        .public
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    let bind = format!("{}://{}:{}", p.bind.transport, p.bind.address, p.bind.port);
                    println!("{:<14} {:<22} {}", p.name, bind, hex);
                }
            }
        }

        Commands::RotateIdentity { profile, config } => {
            #[cfg(target_os = "linux")]
            {
                let s = std::fs::read_to_string(&config)?;
                let cfg: config::server::ServerConfig = config::parse_server_config(&s)?;
                let p = cfg
                    .profiles
                    .iter()
                    .find(|p| p.name == profile)
                    .ok_or_else(|| {
                        anyhow::anyhow!("profile '{}' not found in {}", profile, config.display())
                    })?;
                let kp = server::generate_profile_key(p)?;
                let hex: String = kp
                    .public
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                println!(
                    "Rotated identity for profile '{}'.\nNew server public key:\n  {}",
                    profile, hex
                );
                eprintln!("Restart qeli for the new key to take effect, then set this value as\n  auth.server_public_key on clients of profile '{}' (else they get SERVER KEY MISMATCH).", profile);
            }
        }

        Commands::AddClient {
            username,
            password,
            profiles,
            static_ip,
            max_sessions,
            link,
            link_profile,
            host,
            config,
        } => {
            #[cfg(target_os = "linux")]
            {
                add_client(
                    username,
                    password,
                    profiles,
                    static_ip,
                    max_sessions,
                    link,
                    link_profile,
                    host,
                    config,
                )?;
            }
        }
        Commands::SetWebPassword {
            username,
            password,
            no_enable,
            config,
        } => {
            #[cfg(target_os = "linux")]
            {
                set_web_password(username, password, !no_enable, config)?;
            }
        }
    }

    Ok(())
}

/// Implement `qeli add-client`: append a user to the users file (Argon2-hashed
/// password) and optionally emit a `qeli://` share link for QR import.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn add_client(
    username: String,
    password: Option<String>,
    profiles: Option<String>,
    static_ip: Option<String>,
    max_sessions: u32,
    link: bool,
    link_profile: Option<String>,
    host: Option<String>,
    config: PathBuf,
) -> anyhow::Result<()> {
    use config::users::{UserEntry, UsersDb};

    // Resolve the users file from the server config.
    let cfg_str = std::fs::read_to_string(&config)
        .map_err(|e| anyhow::anyhow!("cannot read server config {}: {}", config.display(), e))?;
    let server_cfg: config::server::ServerConfig = config::parse_server_config(&cfg_str)?;
    let users_file = server_cfg.auth.users_file.clone();

    let mut db = UsersDb::load(&users_file)
        .map_err(|e| anyhow::anyhow!("cannot load users file {}: {}", users_file, e))?;
    if db.users.iter().any(|u| u.username == username) {
        anyhow::bail!("user '{}' already exists in {}", username, users_file);
    }

    // Use the supplied password or generate a strong random one to print once.
    let (plaintext, generated) = match password {
        Some(p) if !p.is_empty() => (p, false),
        _ => (generate_password(20), true),
    };

    // Argon2id hash with a fresh random salt (same scheme as the web API).
    let password_hash = {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        argon2::Argon2::default()
            .hash_password(plaintext.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("hashing failed: {}", e))?
            .to_string()
    };

    let profile_list: Vec<String> = profiles
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let entry = UserEntry {
        username: username.clone(),
        password_hash,
        // Reversibly-encrypted copy so the panel can re-issue this user's config/QR
        // later without the plaintext (best-effort; None if the panel key is absent).
        password_enc: qeli::crypto::secret::encrypt_password(&plaintext).ok(),
        static_ip,
        enabled: true,
        max_sessions,
        profiles: profile_list,
        ..Default::default()
    };
    db.users.push(entry);
    db.save(&users_file)
        .map_err(|e| anyhow::anyhow!("cannot write users file {}: {}", users_file, e))?;

    println!("Added client '{}' to {}", username, users_file);
    if generated {
        println!(
            "Generated password (store it now — only the hash is kept):\n  {}",
            plaintext
        );
    }
    eprintln!("Reload/restart qeli for the new user to take effect.");

    // Optional qeli:// share link (QR-friendly) for one-shot phone import.
    if link {
        let host = host.ok_or_else(|| {
            anyhow::anyhow!("--link requires --host (the server's public address)")
        })?;
        let (host, host_port) = match host.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.parse::<u16>().ok())
            }
            _ => (host, None),
        };
        let profile = match link_profile {
            Some(name) => server_cfg
                .profiles
                .iter()
                .find(|p| p.name == name)
                .ok_or_else(|| anyhow::anyhow!("profile '{}' not found", name))?,
            None => server_cfg
                .profiles
                .first()
                .ok_or_else(|| anyhow::anyhow!("no profiles defined in {}", config.display()))?,
        };
        let kp = server::load_or_generate_profile_key(profile)?;
        let server_key: String = kp
            .public
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let obf = &profile.obfuscation;
        // Real-TLS REALITY profile → client wire mode is `reality-tls` + short_id.
        let rp = &obf.tls.reality_proxy;
        let (mode, reality_sid) = if rp.real_tls && !rp.short_ids.is_empty() {
            ("reality-tls".to_string(), Some(rp.short_ids[0].clone()))
        } else {
            (obf.mode.clone(), None)
        };
        let link = config::share::ClientLink {
            host,
            port: host_port.unwrap_or(profile.bind.port),
            user: username,
            pass: plaintext,
            proto: profile.bind.transport.clone(),
            mode,
            server_key,
            sni: Some(obf.tls.server_name.clone()).filter(|s| !s.is_empty()),
            reality_sid,
            obfs_key: Some(obf.obfs_key.clone()).filter(|s| !s.is_empty()),
            fronting: Some(obf.fronting.clone()).filter(|s| !s.is_empty() && s != "websocket"),
            quic: obf.quic.enabled,
            // mtu=0 (auto): the client adopts the server-pushed TUN MTU. Omitted
            // from the URI; set a non-zero value only to force a client override.
            mtu: 0,
            // URL-safe label (only RFC 3986 unreserved chars) so the qeli://
            // fragment stays human-readable — e.g. `#reality-tls-443` instead of
            // the percent-encoded `#reality-tls%20%28443%29`.
            label: Some(format!(
                "{}-{}",
                profile.name,
                host_port.unwrap_or(profile.bind.port)
            )),
        };
        println!(
            "\nShare link (qeli://) — scan as QR or paste into the app:\n{}",
            link.to_uri()
        );
    }

    Ok(())
}

/// Implement `qeli set-web-password`: hash (or generate) the panel admin
/// password and write `web.username` / `web.password_hash` (and `web.enabled`)
/// into the server config's `[web]` section, preserving the file's comments.
#[cfg(target_os = "linux")]
fn set_web_password(
    username: String,
    password: Option<String>,
    enable: bool,
    config: PathBuf,
) -> anyhow::Result<()> {
    let cfg_str = std::fs::read_to_string(&config)
        .map_err(|e| anyhow::anyhow!("cannot read server config {}: {}", config.display(), e))?;
    // Validate the existing file parses before we touch it, so we never overwrite
    // a broken config (and so the [web] section we edit is well-formed).
    config::parse_server_config(&cfg_str).map_err(|e| {
        anyhow::anyhow!(
            "{} does not parse as a server config: {}",
            config.display(),
            e
        )
    })?;

    let (plaintext, generated) = match password {
        Some(p) if !p.is_empty() => (p, false),
        _ => (generate_password(20), true),
    };

    // Argon2id with a fresh random salt (same scheme as the web API / add-client).
    let password_hash = {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        argon2::Argon2::default()
            .hash_password(plaintext.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("hashing failed: {}", e))?
            .to_string()
    };

    let mut updates: Vec<(&str, String)> = vec![
        ("username", username.clone()),
        ("password_hash", password_hash),
    ];
    if enable {
        updates.push(("enabled", "true".to_string()));
    }

    let new_cfg = set_web_keys(&cfg_str, &updates);
    // Re-parse the edited config as a safety net before writing it back.
    config::parse_server_config(&new_cfg)
        .map_err(|e| anyhow::anyhow!("internal error: edited config no longer parses: {}", e))?;
    std::fs::write(&config, &new_cfg)
        .map_err(|e| anyhow::anyhow!("cannot write {}: {}", config.display(), e))?;

    println!(
        "Web panel admin set: user '{}' in {}",
        username,
        config.display()
    );
    if generated {
        println!(
            "Generated password (store it now — only the hash is kept):\n  {}",
            plaintext
        );
    }
    if enable {
        println!("Web panel enabled (web.enabled = true).");
    } else {
        println!("NOTE: web.enabled left unchanged — set it true to serve the panel.");
    }
    eprintln!("Restart qeli for the change to take effect (e.g. systemctl restart qeli).");
    Ok(())
}

/// Upsert `key = value` pairs inside the `[web]` section of a flat-INI config,
/// preserving comments and all other content. An active (non-comment) line for a
/// key is replaced in place; missing keys are appended to the end of the `[web]`
/// section; if there is no `[web]` section, one is created at the end of the file.
#[cfg(target_os = "linux")]
fn set_web_keys(original: &str, updates: &[(&str, String)]) -> String {
    // Does `line_trimmed` start an active `key = ...` / `key=...` assignment?
    fn is_active_key(line_trimmed: &str, key: &str) -> bool {
        if line_trimmed.starts_with('#') || line_trimmed.starts_with(';') {
            return false;
        }
        match line_trimmed.strip_prefix(key) {
            Some(rest) => rest.trim_start().starts_with('='),
            None => false,
        }
    }

    let mut out: Vec<String> = Vec::new();
    let mut in_web = false;
    let mut web_seen = false;
    let mut written: Vec<String> = Vec::new();

    for line in original.lines() {
        let t = line.trim_start();
        let is_header = t.starts_with('[') && t.trim_end().ends_with(']');
        if is_header {
            // Leaving a section: emit any [web] keys we haven't placed yet.
            if in_web {
                for u in updates {
                    if !written.iter().any(|w| w == u.0) {
                        out.push(format!("{} = {}", u.0, u.1));
                    }
                }
            }
            in_web = t.trim_end() == "[web]";
            if in_web {
                web_seen = true;
                written.clear();
            }
            out.push(line.to_string());
            continue;
        }
        if in_web {
            let mut replaced = false;
            for u in updates {
                if !written.iter().any(|w| w == u.0) && is_active_key(t, u.0) {
                    out.push(format!("{} = {}", u.0, u.1));
                    written.push(u.0.to_string());
                    replaced = true;
                    break;
                }
            }
            if replaced {
                continue;
            }
        }
        out.push(line.to_string());
    }

    // [web] was the final section: flush any remaining keys at EOF.
    if in_web {
        for u in updates {
            if !written.iter().any(|w| w == u.0) {
                out.push(format!("{} = {}", u.0, u.1));
            }
        }
    }
    // No [web] section at all: append a fresh one.
    if !web_seen {
        out.push(String::new());
        out.push("[web]".to_string());
        for u in updates {
            out.push(format!("{} = {}", u.0, u.1));
        }
    }

    let mut s = out.join("\n");
    if original.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Generate a random alphanumeric password of `len` characters.
#[cfg(target_os = "linux")]
fn generate_password(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn print_response(resp: &str) {
    match serde_json::from_str::<serde_json::Value>(resp) {
        Ok(v) => {
            if v["ok"].as_bool().unwrap_or(false) {
                if let Some(msg) = v["message"].as_str() {
                    println!("OK: {}", msg);
                } else {
                    println!("OK");
                }
            } else {
                let err = v["error"].as_str().unwrap_or("unknown error");
                eprintln!("Error: {}", err);
                std::process::exit(1);
            }
        }
        Err(_) => println!("{}", resp),
    }
}

fn print_list_clients(resp: &str) -> anyhow::Result<()> {
    let v: serde_json::Value = serde_json::from_str(resp)?;
    if !v["ok"].as_bool().unwrap_or(false) {
        let err = v["error"].as_str().unwrap_or("unknown error");
        anyhow::bail!("Error: {}", err);
    }

    let clients = match v["clients"].as_array() {
        Some(c) => c,
        None => {
            println!("No clients connected.");
            return Ok(());
        }
    };

    if clients.is_empty() {
        println!("No clients connected.");
        return Ok(());
    }

    // Таблица вывода
    println!(
        "{:<14} {:<12} {:<22} {:<9} {:<10} {:<10} {:<9}",
        "USERNAME", "IP", "SOURCE", "UPTIME", "SENT", "RECV", "BW LIMIT"
    );
    println!("{}", "─".repeat(92));

    for c in clients {
        let username = c["username"].as_str().unwrap_or("-");
        let ip = c["ip"].as_str().unwrap_or("-");
        let peer = c["peer"].as_str().unwrap_or("-");
        let secs = c["connected_secs"].as_u64().unwrap_or(0);
        let bytes_sent = c["bytes_sent"].as_u64().unwrap_or(0);
        let bytes_recv = c["bytes_recv"].as_u64().unwrap_or(0);
        let bw = c["bandwidth_limit_mbps"].as_u64().unwrap_or(0);

        let uptime = format_duration(secs);
        let sent = format_bytes(bytes_sent);
        let recv = format_bytes(bytes_recv);
        let bw_str = if bw == 0 {
            "unlimited".to_string()
        } else {
            format!("{} Mbps", bw)
        };

        println!(
            "{:<14} {:<12} {:<22} {:<9} {:<10} {:<10} {:<9}",
            username, ip, peer, uptime, sent, recv, bw_str
        );
    }

    Ok(())
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::set_web_keys;

    fn ups() -> Vec<(&'static str, String)> {
        vec![
            ("username", "admin".to_string()),
            ("password_hash", "$argon2id$HASH".to_string()),
            ("enabled", "true".to_string()),
        ]
    }

    #[test]
    fn replaces_active_keys_in_web_and_preserves_comments_and_other_sections() {
        let cfg = "\
[auth]
# password_hash here means the algorithm, must NOT be touched
password_hash = argon2id

[web]
enabled = false
# password_hash = $argon2id$OLD  (commented example — leave as comment)
username = old
secure_cookie = true
";
        let out = set_web_keys(cfg, &ups());
        // [auth] algorithm line untouched
        assert!(out.contains("password_hash = argon2id"));
        // [web] active keys replaced in place
        assert!(out.contains("enabled = true"));
        assert!(out.contains("username = admin"));
        assert!(!out.contains("username = old"));
        // commented example preserved verbatim
        assert!(out.contains("# password_hash = $argon2id$OLD"));
        // a fresh active password_hash added (flushed at end of [web] section)
        assert!(out.contains("password_hash = $argon2id$HASH"));
        // unrelated [web] key kept
        assert!(out.contains("secure_cookie = true"));
    }

    #[test]
    fn appends_web_section_when_absent() {
        let cfg = "[auth]\nusers_file = /etc/qeli/users.json\n";
        let out = set_web_keys(cfg, &ups());
        assert!(out.contains("[web]"));
        assert!(out.contains("username = admin"));
        assert!(out.contains("password_hash = $argon2id$HASH"));
        assert!(out.contains("enabled = true"));
        // original content preserved
        assert!(out.contains("users_file = /etc/qeli/users.json"));
    }

    #[test]
    fn web_is_last_section_keys_flush_at_eof() {
        let cfg = "[web]\nbind = 0.0.0.0:8080\n";
        let out = set_web_keys(cfg, &ups());
        assert!(out.contains("bind = 0.0.0.0:8080"));
        assert!(out.contains("password_hash = $argon2id$HASH"));
        // no duplicate [web] header
        assert_eq!(out.matches("[web]").count(), 1);
    }
}
