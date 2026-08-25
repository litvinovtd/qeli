// Modules live in the library crate (`src/lib.rs`) so the realtls FFI can be
// cross-compiled as a cdylib for Android/Windows. The binary only drives the CLI
// (server/client), which is Linux-only — build the cdylib with `--lib`.
use qeli::config;
#[cfg(target_os = "linux")]
use qeli::{client, server};

#[cfg(not(target_os = "linux"))]
compile_error!("the qeli *binary* is Linux-only (the realtls FFI library is cross-platform)");

// A glibc-allocator server is valid for debug/test work, but must never become a
// deployable release binary: under handshake churn its retained arenas caused the
// production RSS regression that jemalloc was introduced to prevent. Keep the guard
// in this binary target so FFI cdylibs and the standalone router client stay isolated.
#[cfg(all(target_os = "linux", not(debug_assertions), not(feature = "jemalloc")))]
compile_error!("release qeli server builds require --features jemalloc");

use clap::{Parser, Subcommand};
use std::path::PathBuf;

// Server builds (`--features jemalloc`) swap in jemalloc as the global allocator.
// glibc malloc retains freed arenas → the data-plane worker's RSS plateaus around
// ~180 MB under handshake churn (up to 8 arenas × ~20 MB, never returned to the OS).
// jemalloc fragments far less and decays freed pages back to the kernel, keeping RSS
// bounded (~40-60 MB). Only defined for the Linux binary (main.rs is Linux-only) and
// only when the opt-in feature is on, so the FFI cdylib and router client are
// untouched. Universal: the allocator ships inside the binary → identical bounded
// behaviour on any server regardless of the host libc/distro.
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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
    /// Validate a config file and exit — no listeners, no TUN, no service.
    ///
    /// Reports three things the normal startup path cannot tell you apart:
    /// syntax errors, schema errors (the same checks the data-plane worker runs),
    /// and keys nothing ever reads — i.e. typos, which are otherwise silent.
    #[command(name = "check-config")]
    CheckConfig {
        #[arg(short, long, default_value = "/etc/qeli/server.conf")]
        config: PathBuf,
        /// Validate as a client config (`[qeli]`) instead of a server config.
        #[arg(long)]
        client: bool,
    },
    /// Run in client mode
    Client {
        #[arg(short, long, default_value = "/etc/qeli/client.conf")]
        config: PathBuf,
    },
    /// List currently connected clients
    #[command(name = "list-clients")]
    ListClients {
        #[arg(long, default_value_t = qeli::server::control::control_socket_path())]
        socket: String,
    },
    /// Forcefully disconnect a user
    Kick {
        username: String,
        #[arg(long, default_value_t = qeli::server::control::control_socket_path())]
        socket: String,
    },
    /// Set bandwidth limit for a user (0 = unlimited)
    #[command(name = "set-bandwidth")]
    SetBandwidth {
        username: String,
        /// Bandwidth limit in Mbit/s (0 = unlimited)
        mbps: u32,
        #[arg(long, default_value_t = qeli::server::control::control_socket_path())]
        socket: String,
    },
    /// Show routes configured for a user
    #[command(name = "show-routes")]
    ShowRoutes {
        username: String,
        #[arg(long, default_value_t = qeli::server::control::control_socket_path())]
        socket: String,
    },
    /// Disable user permanently (kick + block reconnects)
    #[command(name = "disable-user")]
    DisableUser {
        username: String,
        #[arg(long, default_value_t = qeli::server::control::control_socket_path())]
        socket: String,
    },
    /// Re-enable a previously disabled user
    #[command(name = "enable-user")]
    EnableUser {
        username: String,
        #[arg(long, default_value_t = qeli::server::control::control_socket_path())]
        socket: String,
    },
    /// List IPs currently blocked by brute-force protection (wrong-password lockout)
    #[command(name = "list-blocked")]
    ListBlocked {
        #[arg(long, default_value_t = qeli::server::control::control_socket_path())]
        socket: String,
    },
    /// Unblock an IP locked by brute-force protection (or --all to clear every IP)
    #[command(name = "unblock")]
    Unblock {
        /// IP address to unblock (omit when using --all)
        ip: Option<String>,
        /// Unblock every currently-blocked IP
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = qeli::server::control::control_socket_path())]
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
        /// Password (plaintext). VISIBLE TO EVERY LOCAL USER in /proc/<pid>/cmdline and in
        /// the shell history — prefer --password-stdin, or omit it entirely and let a
        /// strong random one be generated and printed once (it cannot be recovered later;
        /// only the hash is stored).
        #[arg(short, long)]
        password: Option<String>,
        /// Read the password from stdin (first line), so it never appears in the process
        /// list. `echo -n 's3cret' | qeli add-client alice --password-stdin`.
        ///
        /// Process arguments on Linux are world-readable through /proc, and both this and
        /// `set-web-password` accepted the secret only that way — so any unprivileged local
        /// account polling /proc during a `sudo qeli add-client … --password …` captured a
        /// VPN credential, or the panel admin password. They also land in auditd's execve
        /// records and in whatever collects them. (Audit 2026-08-04.)
        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,
        /// Restrict this client to these profiles (comma-separated). Empty = all profiles.
        #[arg(long)]
        profiles: Option<String>,
        /// Static tunnel IP for this client (optional).
        #[arg(long)]
        static_ip: Option<String>,
        /// Static IPv6 tunnel address for this client (optional).
        #[arg(long)]
        static_ipv6: Option<String>,
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
    /// Print a `qeli://` share link for an EXISTING user — the CLI equivalent of the
    /// panel's share/QR button, and the answer to "how do I re-send a client its config".
    ///
    /// The password is NOT retyped: it comes from the reversibly-encrypted copy stored
    /// beside the Argon2 hash when the user was created (the hash itself is one-way and
    /// can never be turned back into a link). A user created before that copy existed —
    /// or after the panel key changed — has nothing to recover, so the link can only be
    /// issued by RESETTING the password (`--reset`), which invalidates the config that
    /// user is currently using.
    ShareLink {
        /// Existing username to issue the link for.
        username: String,
        /// Server's public reachable address for the link (host or host:port). Falls back
        /// to `web.public_host` from the config.
        #[arg(long)]
        host: Option<String>,
        /// Profile to build the link for (defaults to the first profile).
        #[arg(long)]
        profile: Option<String>,
        /// Label shown in the client UI (defaults to `<profile>-<port>`).
        #[arg(long)]
        label: Option<String>,
        /// Generate and store a NEW password when none can be recovered. The user's
        /// current config STOPS WORKING; the new password is printed once.
        #[arg(long)]
        reset: bool,
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
        /// Password (plaintext). VISIBLE TO EVERY LOCAL USER in /proc/<pid>/cmdline —
        /// prefer --password-stdin, or omit it and let a strong random one be generated
        /// and printed once (only the Argon2id hash is stored in the config).
        #[arg(short, long)]
        password: Option<String>,
        /// Read the password from stdin (first line) so it never reaches the process list.
        /// See the note on `add-client --password-stdin`. (Audit 2026-08-04.)
        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,
        /// Only set credentials; do NOT flip web.enabled = true.
        #[arg(long)]
        no_enable: bool,
        #[arg(short, long, default_value = "/etc/qeli/server.conf")]
        config: PathBuf,
    },
    /// Install the polkit rule that lets the non-root service user restart its own
    /// systemd unit from the web panel's "Apply & Restart" (action
    /// `org.freedesktop.systemd1.manage-units`, scoped to that one user + unit).
    /// The .deb ships this rule; run this ONLY for a non-.deb install where the
    /// panel reports it is missing. Must run as root: `sudo qeli install-polkit`.
    #[command(name = "install-polkit")]
    InstallPolkit {
        /// systemd unit the panel is allowed to restart.
        #[arg(long, default_value = "qeli.service")]
        unit: String,
        /// Service user the rule authorises (the user qeli runs as).
        #[arg(long, default_value = "qeli")]
        user: String,
        /// Print the rule and target path, but do not write anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Choose the OS user the qeli systemd service runs as: `qeli` (default,
    /// unprivileged, least-privilege) or `root`. Writes a systemd drop-in override
    /// under /etc/systemd/system/<unit>.d/ — it never edits the packaged unit, so the
    /// choice survives package upgrades. Run as root; restart the service to apply.
    #[command(name = "set-service-user")]
    SetServiceUser {
        /// `qeli` (default, hardened) or `root` (no privilege separation).
        #[arg(value_parser = ["qeli", "root"])]
        user: String,
        /// systemd unit to override.
        #[arg(long, default_value = "qeli.service")]
        unit: String,
        /// Show what would change; touch nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the version; with `--check`, ask GitHub Releases whether a newer one
    /// exists. The check is opt-in and user-initiated: it makes ONE unauthenticated
    /// request to public release metadata (no telemetry, no identifying data) and
    /// only reports — it never downloads or installs anything.
    Version {
        /// Check GitHub for a newer release (makes one outbound HTTPS request).
        #[arg(long)]
        check: bool,
    },
}

/// Read just the `logging` section from a config file so the logger can be set
/// up before the rest of the config is parsed. Falls back to (info, stderr) on
/// any error — the real parse later will surface config problems.
fn peek_logging(path: &PathBuf) -> (String, Option<String>, String) {
    if let Ok(s) = std::fs::read_to_string(path) {
        // The only config format is flat INI: read its `[logging]` section.
        if let Ok(doc) = config::format::IniDoc::parse(&s) {
            if let Some(log) = doc.section("logging") {
                let level = log.get_or("level", "info").to_string();
                let file = log
                    .get("file")
                    .filter(|f| !f.is_empty())
                    .map(str::to_string);
                let time_format = log.get_or("time_format", "datetime").to_string();
                return (level, file, time_format);
            }
        }
    }
    ("info".to_string(), None, "datetime".to_string())
}

// The timestamp renderer lives in `qeli::util::log_timestamp` so the server and the
// router/headless client (`client_main.rs`) honour the same `[logging] time_format`.

/// Initialise env_logger at `level`, writing to `file` if given (creating its
/// parent directory), otherwise to stderr (captured by journald under systemd).
/// `RUST_LOG` still overrides the level when set.
fn init_logging(level: &str, file: Option<&str>, time_format: &str) {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level));
    // `time_format = none` drops the prefix entirely (journald/logread/logcat already
    // stamp the line) — emit no leading space in that case.
    let tf = time_format.to_string();
    builder.format(move |buf, record| {
        use std::io::Write;
        let ts = qeli::util::log_timestamp(&tf);
        if ts.is_empty() {
            writeln!(
                buf,
                "{:<5} {}: {}",
                record.level(),
                record.target(),
                record.args()
            )
        } else {
            writeln!(
                buf,
                "{} {:<5} {}: {}",
                ts,
                record.level(),
                record.target(),
                record.args()
            )
        }
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
    let (level, log_file, time_format) = match &cli.command {
        Commands::Server { config } | Commands::Worker { config } | Commands::Client { config } => {
            peek_logging(config)
        }
        _ => ("info".to_string(), None, "datetime".to_string()),
    };
    init_logging(&level, log_file.as_deref(), &time_format);
    // After logging, so arming announces itself. No-op unless QELI_TRACE is set.
    #[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
    qeli::trace::init();

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

        Commands::ListBlocked { socket } => {
            #[cfg(target_os = "linux")]
            {
                let resp =
                    server::control::send_command(&socket, r#"{"cmd":"list-blocked"}"#).await?;
                print_blocked_list(&resp);
            }
        }

        Commands::Unblock { ip, all, socket } => {
            #[cfg(target_os = "linux")]
            {
                let cmd = if all {
                    serde_json::json!({"cmd": "unblock-all"}).to_string()
                } else {
                    let ip = ip.ok_or_else(|| {
                        anyhow::anyhow!("provide an IP address, or --all to unblock everything")
                    })?;
                    serde_json::json!({"cmd": "unblock", "ip": ip}).to_string()
                };
                let resp = server::control::send_command(&socket, &cmd).await?;
                print_response(&resp);
            }
        }

        Commands::CheckConfig { config, client } => {
            let path = config.display().to_string();
            let text = std::fs::read_to_string(&config)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {}", path, e))?;

            // Parse the document ourselves rather than going through
            // parse_*_config(), because the unread-key report needs the same
            // IniDoc the config was built from.
            let doc = config::format::IniDoc::parse(&text)
                .map_err(|e| anyhow::anyhow!("{}: {}", path, e))?;

            let mut problems = 0usize;
            if client {
                let cfg = config::client::ClientConfig::from_ini(&doc)
                    .map_err(|e| anyhow::anyhow!("{}: {}", path, e))?;
                // The same enum checks `run_client` runs, so this command and a real start
                // agree — mirroring what the server branch below already does.
                cfg.validate()
                    .map_err(|e| anyhow::anyhow!("{}: {}", path, e))?;
            } else {
                let cfg = config::server::ServerConfig::from_ini(&doc)
                    .map_err(|e| anyhow::anyhow!("{}: {}", path, e))?;
                // The same schema checks the data-plane worker runs at startup,
                // so `check-config` and a real start agree.
                #[cfg(target_os = "linux")]
                server::validate_profiles(&cfg)?;
                // The supervisor also parses the external users database before it starts
                // the worker. `check-config` used to stop at the main INI, so a malformed or
                // missing users.conf produced "OK" here and then refused the real start.
                // Use the same loader and the same strict outcome as run_supervisor: a missing
                // file is accepted only when inline users/groups make that valid inside the
                // loader itself.
                #[cfg(target_os = "linux")]
                server::load_users_db(&cfg).map_err(|e| {
                    anyhow::anyhow!("{}: users database '{}': {}", path, cfg.auth.users_file, e)
                })?;
                // Pre-flight the addressing against THIS host, so `check-config` on the
                // server answers the question that matters before a first start: would
                // this config cut me off the box? Reported (not `?`) because the verdict
                // is host-specific — checking a server's config from a laptop compares it
                // against the laptop's networking, where a "collision" means nothing.
                #[cfg(target_os = "linux")]
                if let Err(e) = server::preflight::run(&cfg) {
                    problems += 1;
                    eprintln!("{path}: would NOT start on this host — {e}");
                }
                #[cfg(not(target_os = "linux"))]
                let _ = &cfg;
            }

            // Keys nothing read: not a parse error, never surfaced at runtime,
            // and the reason a misspelling silently keeps the default.
            //
            // A client config is shared with the Windows/macOS clients, which have
            // their own parser and implement a few keys this binary does not. Those
            // are perfectly valid here — reporting them as typos would be a lie —
            // so they are listed separately and do not fail the check.
            // Keys removed in 0.7.12 because they never had any effect. An existing
            // config may still carry them, and calling those a "typo" would send the
            // operator hunting for a spelling mistake that isn't there. Name them for
            // what they are, and don't fail the check — deleting the line is optional
            // tidying, not a fix.
            // NB: `[logging] format` is deliberately absent. It is still parsed into
            // the config (it just isn't applied), so it never lands in unread_keys and
            // could never be reported here — listing it would promise a message that
            // can't happen. It is marked "not implemented" in CONFIG.md instead.

            let (gui_only, rest): (Vec<_>, Vec<_>) = doc
                .unread_keys()
                .into_iter()
                .partition(|(section, key)| client && config::is_gui_only_client_key(section, key));
            let (retired, unknown): (Vec<_>, Vec<_>) = rest
                .into_iter()
                .partition(|(section, key)| config::is_retired_key(section, key));

            if !gui_only.is_empty() {
                println!(
                    "{}: {} key(s) used only by the Windows/macOS clients (ignored here):",
                    path,
                    gui_only.len()
                );
                for (section, key) in &gui_only {
                    println!("  {} {}", section, key);
                }
            }

            if !retired.is_empty() {
                println!(
                    "{}: {} key(s) retired in 0.7.12 — they never had any effect:",
                    path,
                    retired.len()
                );
                for (section, key) in &retired {
                    println!("  {} {}", section, key);
                }
                println!("Safe to delete; leaving them changes nothing either way.");
            }

            if !unknown.is_empty() {
                problems += unknown.len();
                eprintln!(
                    "{}: {} key(s) that nothing reads — check the spelling:",
                    path,
                    unknown.len()
                );
                for (section, key) in &unknown {
                    eprintln!("  {} {}", section, key);
                }
                eprintln!(
                    "An unknown key is not an error: it is simply ignored, and the setting \
                     keeps its default."
                );
            }

            // Values that were PRESENT but not understood. `unread_keys` above only finds
            // misspelled key NAMES; a key spelled correctly whose VALUE is junk was read,
            // so it never appears there — it only produced a log line the worker emits at
            // runtime, which `check-config` never saw. That is how a config containing
            // `kill_switch = ture` passed with "OK" and rc=0 while the kill-switch was
            // silently off. Reported and counted as a problem now. (S-15)
            let bad_values = doc.bad_values();
            if !bad_values.is_empty() {
                problems += bad_values.len();
                eprintln!(
                    "{}: {} value(s) present but not understood — the default was used instead:",
                    path,
                    bad_values.len()
                );
                for msg in &bad_values {
                    eprintln!("  {msg}");
                }
            }

            if problems == 0 {
                println!("{}: OK", path);
            } else {
                std::process::exit(1);
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
            password_stdin,
            profiles,
            static_ip,
            static_ipv6,
            max_sessions,
            link,
            link_profile,
            host,
            config,
        } => {
            let password = read_password_arg(password, password_stdin)?;
            #[cfg(target_os = "linux")]
            {
                add_client(
                    username,
                    password,
                    profiles,
                    static_ip,
                    static_ipv6,
                    max_sessions,
                    link,
                    link_profile,
                    host,
                    config,
                )?;
            }
        }
        Commands::ShareLink {
            username,
            host,
            profile,
            label,
            reset,
            config,
        } => {
            #[cfg(target_os = "linux")]
            {
                share_link(username, host, profile, label, reset, config)?;
            }
        }
        Commands::SetWebPassword {
            username,
            password,
            password_stdin,
            no_enable,
            config,
        } => {
            let password = read_password_arg(password, password_stdin)?;
            #[cfg(target_os = "linux")]
            {
                set_web_password(username, password, !no_enable, config)?;
            }
        }

        Commands::InstallPolkit {
            unit,
            user,
            dry_run,
        } => {
            #[cfg(target_os = "linux")]
            {
                install_polkit(unit, user, dry_run)?;
            }
        }

        Commands::SetServiceUser {
            user,
            unit,
            dry_run,
        } => {
            #[cfg(target_os = "linux")]
            {
                set_service_user(user, unit, dry_run)?;
            }
        }

        Commands::Version { check } => {
            println!("qeli {}", env!("CARGO_PKG_VERSION"));
            if check {
                #[cfg(target_os = "linux")]
                {
                    // Opt-in, user-initiated, notification-only (see server::update docs):
                    // we print the update COMMAND for the operator to run — qeli itself
                    // never downloads or installs anything.
                    match server::update::check_latest().await {
                        Ok(rel) if rel.is_newer => {
                            println!("Update available: {} → {}", rel.tag, rel.url);
                            print_update_command(&rel);
                        }
                        Ok(_) => println!("You are on the latest version."),
                        Err(e) => {
                            eprintln!("Could not check for updates: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// The polkit rule text, templated for a given service `user` and systemd `unit`.
/// Mirrors the .deb's `debian/49-qeli.rules`, but lets a hand-install target a unit
/// or user named differently from the defaults.
#[cfg(target_os = "linux")]
fn validate_service_unit(unit: &str) -> anyhow::Result<()> {
    if unit.is_empty()
        || unit.len() > 255
        || !unit.ends_with(".service")
        || !unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@' | b':'))
    {
        anyhow::bail!(
            "invalid systemd service unit `{unit}`: expected a simple *.service name using only ASCII letters, digits, _, -, ., @ or :"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_service_user(user: &str) -> anyhow::Result<()> {
    let first_ok = user
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
    if !first_ok
        || user.len() > 64
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        anyhow::bail!(
            "invalid service user `{user}`: expected a simple account name using only ASCII letters, digits, _, - or ."
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_admin_command(program: &str, args: &[&str], purpose: &str) -> anyhow::Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|error| anyhow::anyhow!("{purpose}: cannot run {program}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "{purpose}: {program} {} exited with {}: {}",
        args.join(" "),
        output.status,
        detail.trim()
    )
}

#[cfg(target_os = "linux")]
fn render_polkit_rule(user: &str, unit: &str) -> String {
    format!(
        "// polkit rule: allow the unprivileged `{user}` service user to restart its OWN\n\
         // systemd unit `{unit}` from the qeli web panel (\"Apply & Restart\"). Written by\n\
         // `qeli install-polkit`; the .deb ships an equivalent. Scoped narrowly: ONLY user\n\
         // `{user}`, ONLY manage-units on `{unit}`. No other privilege is granted.\n\
         polkit.addRule(function(action, subject) {{\n\
         \x20   if (action.id == \"org.freedesktop.systemd1.manage-units\" &&\n\
         \x20       subject.user == \"{user}\") {{\n\
         \x20       var unit = action.lookup(\"unit\");\n\
         \x20       if (unit == \"{unit}\") {{\n\
         \x20           return polkit.Result.YES;\n\
         \x20       }}\n\
         \x20   }}\n\
         }});\n"
    )
}

/// Implement `qeli install-polkit`: write the polkit rule that lets the non-root
/// service user restart its own systemd unit from the panel. Needed only for
/// non-.deb installs (the .deb ships the rule). Must run as root.
#[cfg(target_os = "linux")]
fn install_polkit(unit: String, user: String, dry_run: bool) -> anyhow::Result<()> {
    validate_service_unit(&unit)?;
    validate_service_user(&user)?;
    let dest = std::path::Path::new("/etc/polkit-1/rules.d/49-qeli.rules");
    let rule = render_polkit_rule(&user, &unit);

    if dry_run {
        println!(
            "# would write {} (user={user}, unit={unit}):\n",
            dest.display()
        );
        print!("{rule}");
        return Ok(());
    }

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!(
            "install-polkit must run as root — retry with:\n  \
             sudo qeli install-polkit --unit {unit} --user {user}"
        );
    }

    let dir = dest.parent().expect("rule path has a parent");
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("cannot create {}: {}", dir.display(), e))?;
    qeli::util::write_atomic_private(dest, rule.as_bytes())
        .map_err(|e| anyhow::anyhow!("cannot write {}: {}", dest.display(), e))?;
    // World-readable, not secret — polkitd reads it (same mode the .deb installs).
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| anyhow::anyhow!("cannot protect {}: {}", dest.display(), e))?;

    println!("Installed polkit rule → {}", dest.display());
    println!("  user = {user}");
    println!("  unit = {unit}");
    println!(
        "polkitd picks this up automatically (no reload needed). Click \"Apply & Restart\" in the\n\
         panel again — or run `systemctl restart {unit}` — to apply your changes."
    );
    if user == "qeli" && unit != "qeli.service" {
        eprintln!(
            "note: your unit is not the default qeli.service. Make sure {unit} really runs as \
             User={user}."
        );
    }
    Ok(())
}

/// Implement `qeli set-service-user`: pick whether the systemd service runs as the
/// unprivileged `qeli` user (default) or as root, via a drop-in override so the choice
/// survives package upgrades. Must run as root. For `root` it writes User=root/Group=root;
/// for `qeli` it removes the override (the packaged unit already runs as qeli) and hands
/// /etc/qeli ownership back so the unprivileged service can write it.
#[cfg(target_os = "linux")]
fn set_service_user(user: String, unit: String, dry_run: bool) -> anyhow::Result<()> {
    validate_service_unit(&unit)?;
    let dir = format!("/etc/systemd/system/{unit}.d");
    let dropin = format!("{dir}/run-as.conf");
    let as_root = user == "root";

    let content = format!(
        "# Written by `qeli set-service-user root`. Runs {unit} as ROOT instead of the\n\
         # unprivileged `qeli` user — a compromise of the daemon then means root on the\n\
         # host (least privilege is lost). Revert with `qeli set-service-user qeli` (or\n\
         # delete this file). The packaged unit's hardening (ProtectSystem, NoNewPrivileges,\n\
         # a bounded capability set) still applies on top of root.\n\
         [Service]\n\
         User=root\n\
         Group=root\n"
    );

    if dry_run {
        if as_root {
            println!("# would write {dropin}:\n{content}");
        } else {
            println!(
                "# would run: chown -R qeli:qeli /etc/qeli,\n# then remove {dropin} \
                 (if present) → revert to the packaged default (User=qeli)"
            );
        }
        println!("# then: systemctl daemon-reload   (restart {unit} to apply)");
        return Ok(());
    }

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!(
            "set-service-user must run as root — retry with: sudo qeli set-service-user {user}"
        );
    }

    if as_root {
        std::fs::create_dir_all(&dir).map_err(|e| anyhow::anyhow!("cannot create {dir}: {e}"))?;
        qeli::util::write_atomic_private(&dropin, content.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot write {dropin}: {e}"))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dropin, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| anyhow::anyhow!("cannot protect {dropin}: {e}"))?;
        println!("{unit} will run as ROOT (drop-in {dropin}).");
        println!("  WARNING: this removes privilege separation — a daemon compromise means root.");
        println!(
            "  Prefer this only when the qeli user cannot work (a kernel/container without\n\
             \x20 ambient capabilities), or to avoid the /etc/qeli ownership + polkit setup."
        );
    } else {
        // Do this BEFORE removing the root override. If ownership repair fails, the unit
        // keeps its last known-working root configuration instead of being switched to an
        // account that cannot read or update its own state.
        if unit == "qeli.service" {
            run_admin_command(
                "chown",
                &["-R", "qeli:qeli", "/etc/qeli"],
                "cannot hand /etc/qeli back to the qeli service account",
            )?;
        }
        match std::fs::remove_file(&dropin) {
            Ok(_) => {
                println!("Removed {dropin} — {unit} reverts to the packaged default (User=qeli).")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("No root override present — {unit} already runs as the qeli user.");
            }
            Err(e) => return Err(anyhow::anyhow!("cannot remove {dropin}: {e}")),
        }
    }

    run_admin_command(
        "systemctl",
        &["daemon-reload"],
        "systemd did not reload the updated service definition",
    )?;
    println!("Run `systemctl restart {unit}` to apply.");
    Ok(())
}

/// Resolve the password for `add-client` / `set-web-password`.
///
/// `--password-stdin` reads the FIRST LINE of stdin, so the secret never appears in
/// `/proc/<pid>/cmdline`, in `ps`, in the shell history, or in auditd's execve record — all
/// of which `--password <value>` puts it in, readable by every local account. A trailing
/// newline is stripped (so `echo -n` and `echo` both work) and nothing else is trimmed: a
/// password may legitimately begin or end with a space.
///
/// `None` from both means "generate one", which is the existing behaviour and the safest
/// default. (Audit 2026-08-04.)
fn read_password_arg(password: Option<String>, from_stdin: bool) -> anyhow::Result<Option<String>> {
    if !from_stdin {
        return Ok(password);
    }
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| anyhow::anyhow!("--password-stdin: cannot read stdin: {e}"))?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    if line.is_empty() {
        anyhow::bail!("--password-stdin: stdin was empty — pipe the password in, e.g. `printf %s 's3cret' | qeli …`");
    }
    Ok(Some(line))
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
    static_ipv6: Option<String>,
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

    // Resolve and validate the optional link target before hashing or appending the user. An
    // unusable IPv6 endpoint must not leave behind an account after the command ultimately
    // fails to produce a client configuration.
    let prepared_link = if link {
        let raw_host = host.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--link requires --host (the server's public address)")
        })?;
        let profile_index = match link_profile.as_deref() {
            Some(name) => server_cfg
                .profiles
                .iter()
                .position(|profile| profile.name == name)
                .ok_or_else(|| anyhow::anyhow!("profile '{}' not found", name))?,
            None => {
                if server_cfg.profiles.is_empty() {
                    anyhow::bail!("no profiles defined in {}", config.display());
                }
                0
            }
        };
        let profile = &server_cfg.profiles[profile_index];
        let (host, port) = config::share::supported_public_endpoint(raw_host, profile.bind.port)
            .map_err(anyhow::Error::msg)?;
        Some((profile_index, host, port))
    } else {
        None
    };

    // Load the existing users DB, or start an empty one when the file doesn't exist yet
    // (first user on a fresh install). Read only — the actual append happens under the
    // cross-process lock below, on a freshly re-read copy; this one is just for the
    // duplicate-name check and for deriving defaults.
    let db = if std::path::Path::new(&users_file).exists() {
        UsersDb::load(&users_file)
            .map_err(|e| anyhow::anyhow!("cannot load users file {}: {}", users_file, e))?
    } else {
        UsersDb {
            users: Vec::new(),
            groups: std::collections::HashMap::new(),
        }
    };
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
        qeli::crypto::password_hasher()
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
        static_ipv6,
        enabled: true,
        max_sessions,
        profiles: profile_list,
        ..Default::default()
    };
    // Append under the cross-process lock, re-reading the file first. Pushing onto the
    // copy loaded earlier and writing the whole thing back raced a RUNNING server: the
    // worker holds its own copy and rewrites the file on any control-socket change, so a
    // client added here could be silently reverted minutes later (seen in the lab).
    let (_, added) = qeli::config::users::UsersDb::update_locked(&users_file, |fresh| {
        // Re-check on the just-read state: the name may have appeared since.
        if fresh.users.iter().any(|u| u.username == entry.username) {
            return Ok(false);
        }
        fresh.users.push(entry);

        // Validate the exact effective file+inline union while the cross-process lock is
        // held. This prevents a concurrent add from creating a duplicate fixed address and
        // keeps CLI, panel, check-config and runtime startup on the same gate.
        let mut effective = fresh.clone();
        let file_users: std::collections::HashSet<String> = effective
            .users
            .iter()
            .map(|user| user.username.clone())
            .collect();
        for inline in &server_cfg.auth.users {
            if !file_users.contains(&inline.username) {
                effective.users.push(inline.clone());
            }
        }
        for (name, group) in &server_cfg.auth.groups {
            effective
                .groups
                .entry(name.clone())
                .or_insert_with(|| group.clone());
        }
        if let Err(error) = qeli::server::validate_static_address_sources(&server_cfg, &effective) {
            fresh.users.pop();
            return Err(error);
        }
        Ok(true)
    })
    .map_err(|e| anyhow::anyhow!("cannot write users file {}: {}", users_file, e))?;
    let added: bool = added.map_err(|error| {
        anyhow::anyhow!("client address validation failed; users file was not changed: {error}")
    })?;
    if !added {
        anyhow::bail!(
            "user '{}' already exists in {} (added concurrently)",
            username,
            users_file
        );
    }

    println!("Added client '{}' to {}", username, users_file);
    if generated {
        println!(
            "Generated password (store it now — only the hash is kept):\n  {}",
            plaintext
        );
    }
    eprintln!("Reload/restart qeli for the new user to take effect.");

    // Optional qeli:// share link (QR-friendly) for one-shot phone import.
    if let Some((profile_index, host, port)) = prepared_link {
        let profile = &server_cfg.profiles[profile_index];
        let kp = server::load_or_generate_profile_key(profile)?;
        let server_key: String = kp
            .public
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        // Profile-dependent fields come from the shared builder (see
        // `ClientLink::for_profile`) — the panel's /api/share and `share-link` use the
        // same one, so the three cannot drift apart.
        let link = config::share::ClientLink::for_profile(
            profile,
            host,
            port,
            username,
            plaintext,
            server_key,
            // URL-safe label (only RFC 3986 unreserved chars) so the qeli:// fragment
            // stays human-readable — e.g. `#reality-tls-443` rather than the
            // percent-encoded `#reality-tls%20%28443%29`.
            Some(format!("{}-{}", profile.name, port)),
        );
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
        qeli::crypto::password_hasher()
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

    let new_cfg = config::set_section_keys(&cfg_str, "web", &updates);
    // Re-parse the edited config as a safety net before writing it back.
    config::parse_server_config(&new_cfg)
        .map_err(|e| anyhow::anyhow!("internal error: edited config no longer parses: {}", e))?;
    qeli::util::write_atomic_private(&config, new_cfg.as_bytes())
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

/// Generate a random alphanumeric password of `len` characters.
#[cfg(target_os = "linux")]
/// Implement `qeli share-link`: re-issue an EXISTING user's `qeli://` config without
/// retyping the password — the CLI counterpart of the panel's share/QR button, sharing its
/// exact semantics (and, via [`ClientLink::for_profile`], its exact link contents).
///
/// The password comes from `password_enc`, the reversibly-encrypted copy written next to
/// the Argon2 hash at creation. The hash alone is one-way, so a user without that copy
/// (created before it existed, or after the panel key changed) cannot be re-issued at all —
/// only reset, which is destructive and therefore opt-in via `--reset`.
#[cfg(target_os = "linux")]
fn share_link(
    username: String,
    host: Option<String>,
    profile_name: Option<String>,
    label: Option<String>,
    reset: bool,
    config: PathBuf,
) -> anyhow::Result<()> {
    let cfg_str = std::fs::read_to_string(&config)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {}", config.display(), e))?;
    let server_cfg: config::server::ServerConfig = config::parse_server_config(&cfg_str)?;

    let profile = match &profile_name {
        Some(name) => server_cfg
            .profiles
            .iter()
            .find(|p| &p.name == name)
            .ok_or_else(|| {
                let loaded: Vec<&str> = server_cfg
                    .profiles
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect();
                anyhow::anyhow!("profile '{}' not found (have: {})", name, loaded.join(", "))
            })?,
        None => server_cfg
            .profiles
            .first()
            .ok_or_else(|| anyhow::anyhow!("no profiles defined in {}", config.display()))?,
    };

    // Host: --host wins, else web.public_host — the same fallback the panel uses, so an
    // operator who set it once needn't repeat it per link.
    let host = host
        .filter(|h| !h.is_empty())
        .or_else(|| Some(server_cfg.web.public_host.clone()).filter(|h| !h.is_empty()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no host: pass --host <addr> or set web.public_host (the server's public address)"
            )
        })?;
    // Validate before password recovery/reset. A malformed or unsupported endpoint must never
    // rotate a user's credentials and only then discover that no usable link can be emitted.
    let (host, port) = config::share::supported_public_endpoint(&host, profile.bind.port)
        .map_err(anyhow::Error::msg)?;

    let users_file = server_cfg.auth.users_file.clone();
    let db = config::users::UsersDb::load(&users_file)
        .map_err(|e| anyhow::anyhow!("cannot read users file {}: {}", users_file, e))?;
    let enc = db
        .users
        .iter()
        .find(|u| u.username == username)
        .ok_or_else(|| anyhow::anyhow!("user '{}' not found in {}", username, users_file))?
        .password_enc
        .clone();

    let recovered = enc
        .as_deref()
        .and_then(|e| qeli::crypto::secret::decrypt_password(e).ok());
    let (plaintext, was_reset) = match recovered {
        Some(p) => (p, false),
        None if !reset => anyhow::bail!(
            "no recoverable password for '{}' (created before re-issue was supported, or the \
             key changed). Re-run with --reset to issue a NEW password — the config this user \
             is currently using will stop working.",
            username
        ),
        None => {
            let new_pw = generate_password(20);
            let hash = {
                use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
                let salt = SaltString::generate(&mut OsRng);
                qeli::crypto::password_hasher()
                    .hash_password(new_pw.as_bytes(), &salt)
                    .map_err(|e| anyhow::anyhow!("hashing failed: {}", e))?
                    .to_string()
            };
            let enc2 = qeli::crypto::secret::encrypt_password(&new_pw).ok();
            // Re-read under the cross-process lock and edit THERE: a running worker holds
            // its own copy and rewrites the file on any control-socket change, so writing
            // back a copy loaded earlier could silently revert it — and the field at stake
            // is a password, i.e. the two ends would disagree on the user's credentials.
            let (_, found) =
                config::users::UsersDb::update_locked(&users_file, |fresh| {
                    match fresh.users.iter_mut().find(|u| u.username == username) {
                        Some(u) => {
                            u.password_hash = hash;
                            u.password_enc = enc2;
                            true
                        }
                        None => false,
                    }
                })
                .map_err(|e| anyhow::anyhow!("cannot write users file {}: {}", users_file, e))?;
            if !found {
                anyhow::bail!(
                    "user '{}' disappeared from {} while resetting",
                    username,
                    users_file
                );
            }
            (new_pw, true)
        }
    };

    let kp = server::load_or_generate_profile_key(profile)?;
    let server_key: String = kp
        .public
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let link = config::share::ClientLink::for_profile(
        profile,
        host,
        port,
        username.clone(),
        plaintext,
        server_key,
        label.or_else(|| Some(format!("{}-{}", profile.name, port))),
    );

    if was_reset {
        println!(
            "Password RESET for '{}' — the previous config no longer works.\nNew password: {}",
            username, link.pass
        );
        // The running worker keeps users in memory; unlike the panel we have no control
        // channel to it, so say plainly what makes the change live.
        println!("Reload the running server to apply: systemctl reload qeli  (or restart it)");
    }
    println!(
        "\nShare link (qeli://) — scan as QR or paste into the app:\n{}",
        link.to_uri()
    );
    Ok(())
}

fn generate_password(len: usize) -> String {
    use rand::prelude::*;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect()
}

/// Print a copy-paste update command matching how this server was installed. qeli
/// never runs it — the operator does. When the release publishes `SHA256SUMS`, the
/// command verifies the download before installing.
#[cfg(target_os = "linux")]
fn print_update_command(rel: &server::update::LatestRelease) {
    match server::update::install_kind() {
        "docker" => {
            println!("\nUpdate (Docker):");
            println!("  docker pull ghcr.io/litvinovtd/qeli:latest \\");
            println!("    && docker restart qeli   # or recreate your container");
        }
        "deb" => match &rel.deb_url {
            Some(deb) => {
                let name = deb.rsplit('/').next().unwrap_or("qeli.deb");
                println!("\nUpdate (.deb) — verify the download, then install:");
                println!("  cd /tmp \\");
                println!("    && curl -fsSLO \"{}\" \\", deb);
                match &rel.sha_url {
                    Some(sha) => {
                        println!("    && curl -fsSLO \"{}\" \\", sha);
                        println!("    && sha256sum --ignore-missing -c SHA256SUMS \\");
                    }
                    None => println!(
                        "    # (no SHA256SUMS published for this release — checksum skipped)"
                    ),
                }
                println!(
                    "    && sudo dpkg -i \"{}\" && sudo systemctl restart qeli",
                    name
                );
            }
            None => println!("\nDownload it from the release page above."),
        },
        _ => println!("\nDownload it from the release page above."),
    }
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

/// Print the `list-blocked` response as a table. The blocked list rides inside the
/// `message` field as a JSON array of {ip, failures, unblock_in_secs}.
fn print_blocked_list(resp: &str) {
    let v: serde_json::Value = match serde_json::from_str(resp) {
        Ok(v) => v,
        Err(_) => {
            println!("{}", resp);
            return;
        }
    };
    if !v["ok"].as_bool().unwrap_or(false) {
        eprintln!("Error: {}", v["error"].as_str().unwrap_or("unknown error"));
        std::process::exit(1);
    }
    let list: Vec<serde_json::Value> = v["message"]
        .as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    if list.is_empty() {
        println!("No blocked IPs.");
        return;
    }
    let fmt_secs = |s: u64| {
        if s >= 60 {
            format!("{}m {}s", s / 60, s % 60)
        } else {
            format!("{}s", s)
        }
    };
    println!(
        "{:<20} {:<10} {:<14}",
        "IP ADDRESS", "FAILURES", "UNBLOCK IN"
    );
    println!("{}", "─".repeat(46));
    for b in &list {
        println!(
            "{:<20} {:<10} {:<14}",
            b["ip"].as_str().unwrap_or("-"),
            b["failures"].as_u64().unwrap_or(0),
            fmt_secs(b["unblock_in_secs"].as_u64().unwrap_or(0)),
        );
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
    // New observability columns are appended so existing column positions stay stable for
    // anyone who already parses this output.
    println!(
        "{:<14} {:<12} {:<22} {:<9} {:<10} {:<10} {:<9} {:<20} {:<8}",
        "USERNAME", "IP", "SOURCE", "UPTIME", "SENT", "RECV", "BW LIMIT", "CLIENT", "DROPS"
    );
    println!("{}", "─".repeat(122));

    for c in clients {
        let username = c["username"].as_str().unwrap_or("-");
        let ip = c["ip"].as_str().unwrap_or("-");
        let peer = c["peer"].as_str().unwrap_or("-");
        let secs = c["connected_secs"].as_u64().unwrap_or(0);
        let bytes_sent = c["bytes_sent"].as_u64().unwrap_or(0);
        let bytes_recv = c["bytes_recv"].as_u64().unwrap_or(0);
        let bw = c["bandwidth_limit_mbps"].as_u64().unwrap_or(0);
        let dropped = c["dropped"].as_u64().unwrap_or(0);
        // Self-reported by the client and validated server-side (`protocol::ctrl`); "-" is
        // a client that predates the report, one that has not sent it yet, or one whose
        // report was refused. Shown as a label — it proves nothing about what is actually
        // running.
        let client = match (c["client_version"].as_str(), c["client_platform"].as_str()) {
            (Some(v), Some(p)) => format!("{v}/{p}"),
            (Some(v), None) => v.to_string(),
            _ => "-".to_string(),
        };

        let uptime = format_duration(secs);
        let sent = format_bytes(bytes_sent);
        let recv = format_bytes(bytes_recv);
        let bw_str = if bw == 0 {
            "unlimited".to_string()
        } else {
            format!("{} Mbps", bw)
        };

        println!(
            "{:<14} {:<12} {:<22} {:<9} {:<10} {:<10} {:<9} {:<20} {:<8}",
            username, ip, peer, uptime, sent, recv, bw_str, client, dropped
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
    use super::{validate_service_unit, validate_service_user};
    use qeli::config::set_section_keys;

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
        let out = set_section_keys(cfg, "web", &ups());
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
        let out = set_section_keys(cfg, "web", &ups());
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
        let out = set_section_keys(cfg, "web", &ups());
        assert!(out.contains("bind = 0.0.0.0:8080"));
        assert!(out.contains("password_hash = $argon2id$HASH"));
        // no duplicate [web] header
        assert_eq!(out.matches("[web]").count(), 1);
    }

    #[test]
    fn administrative_names_cannot_escape_paths_or_polkit_strings() {
        for unit in ["qeli.service", "qeli@edge-1.service", "vpn:test.service"] {
            validate_service_unit(unit).expect("ordinary systemd service name");
        }
        for unit in [
            "../qeli.service",
            "qeli.timer",
            "qeli\".service",
            "qeli\\x2f.service",
        ] {
            assert!(
                validate_service_unit(unit).is_err(),
                "accepted unsafe unit {unit:?}"
            );
        }

        for user in ["qeli", "qeli-worker", "svc.qeli", "_qeli"] {
            validate_service_user(user).expect("ordinary service account name");
        }
        for user in ["-qeli", "qeli\" || true", "qeli/service"] {
            assert!(
                validate_service_user(user).is_err(),
                "accepted unsafe user {user:?}"
            );
        }
    }
}
