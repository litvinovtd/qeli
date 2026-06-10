//! Standalone qeli **client** binary for routers (Keenetic / Entware) and any
//! headless Linux client. It drives only the `client` data plane — no server, no
//! web admin, no `rustls`/`ring` — so it cross-compiles to mipsel/aarch64 musl.
//!
//! Built ONLY under the off-by-default `client-bin` feature (see Cargo.toml and
//! docs/KEENETIC-PORT.md):
//!
//! ```sh
//! cargo build --release --bin qeli-client \
//!   --no-default-features --features client-bin --target <TARGET>
//! ```
//!
//! The full `qeli` daemon (server + client + web) is still `src/main.rs`.

#[cfg(not(target_os = "linux"))]
compile_error!("qeli-client is Linux-only (it creates a TUN device via /dev/net/tun)");

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "qeli-client",
    about = "Obfuscated VPN client (router/headless build)",
    version
)]
struct Cli {
    /// Client config (flat-INI, `[qeli]` section). Default suits Entware layout.
    #[arg(short, long, default_value = "/opt/etc/qeli/client.conf")]
    config: PathBuf,
}

/// Read the `[logging]` section (level + optional file) so logs land where the
/// router operator expects. Mirrors `main.rs::peek_logging`; falls back to
/// (info, stderr) on any error.
fn peek_logging(path: &PathBuf) -> (String, Option<String>) {
    if let Ok(s) = std::fs::read_to_string(path) {
        if let Ok(doc) = qeli::config::format::IniDoc::parse(&s) {
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

fn init_logging(level: &str, file: Option<&str>) {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level));
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
            Err(e) => {
                eprintln!("qeli-client: cannot open log file {path}: {e} — logging to stderr")
            }
        }
    }
    builder.init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let (level, log_file) = peek_logging(&cli.config);
    init_logging(&level, log_file.as_deref());

    let config_str = cli.config.to_str().ok_or_else(|| {
        anyhow::anyhow!("config path is not valid UTF-8: {}", cli.config.display())
    })?;
    log::info!("Starting qeli client with config: {}", cli.config.display());
    qeli::client::run_client(config_str).await
}
