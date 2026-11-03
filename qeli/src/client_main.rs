//! Standalone qeli **client** binary for routers (Keenetic / Entware) and any
//! headless Linux client. It drives only the `client` data plane — no server, no
//! web admin, no `rustls`/`ring` — so it cross-compiles to mipsel/aarch64 musl.
//!
//! Built ONLY under the off-by-default `client-bin` feature (see Cargo.toml and
//! docs/*/reference/KEENETIC-PORT.md):
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
use qeli_core as qeli;
use std::path::PathBuf;

mod embedded_licenses;

#[derive(clap::Subcommand)]
enum Command {
    /// View or export original license resources without loading a VPN configuration.
    Licenses {
        #[arg(long, conflicts_with_all = ["export", "list"])]
        file: Option<String>,
        #[arg(long, conflicts_with = "list")]
        export: Option<PathBuf>,
        #[arg(long)]
        list: bool,
    },
}

#[derive(Parser)]
#[command(
    name = "qeli-client",
    about = "Obfuscated VPN client (router/headless build)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Client config (flat-INI, `[qeli]` section). Default suits Entware layout.
    #[arg(short, long, default_value = "/opt/etc/qeli/client.conf")]
    config: PathBuf,
    /// Validate INI and print core/legacy gateway ownership, then exit without connecting.
    #[arg(long)]
    print_gateway_owner: bool,
    /// Require the configured TUN name to match the router wrapper before launch.
    #[arg(long, requires_all = ["print_gateway_owner", "expect_router_attach"])]
    expect_router_device: Option<String>,
    /// Require the wrapper's owned/attached TUN lifecycle and gateway ownership.
    #[arg(long, requires_all = ["print_gateway_owner", "expect_router_device"])]
    expect_router_attach: Option<bool>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(Command::Licenses { file, export, list }) = cli.command {
        embedded_licenses::run(file.as_deref(), export.as_deref(), list)?;
        return Ok(());
    }
    if cli.print_gateway_owner {
        let expected = cli
            .expect_router_device
            .as_deref()
            .zip(cli.expect_router_attach);
        println!(
            "{}",
            qeli::client::inspect_gateway_owner_with_router_expectation(&cli.config, expected)?
        );
        return Ok(());
    }

    let (level, log_file, time_format) = qeli::client::peek_logging(&cli.config);
    qeli::logging::init(&level, log_file.as_deref(), &time_format, "plain");

    let config_str = cli.config.to_str().ok_or_else(|| {
        anyhow::anyhow!("config path is not valid UTF-8: {}", cli.config.display())
    })?;
    log::info!("Starting qeli client with config: {}", cli.config.display());
    qeli::client::run_client(config_str).await
}

#[cfg(test)]
mod gateway_owner_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    const BASE: &str = "[qeli]\nserver=192.0.2.1:443\nmode=plain\nbind_static=false\ngateway=false\nuser=fixture\npass=canary-secret\n";
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(text: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "qeli-gateway-owner-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, text).unwrap();
            Self(path)
        }
        fn owner(&self) -> anyhow::Result<&'static str> {
            qeli::client::inspect_gateway_owner(&self.0)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    #[test]
    fn metadata_cli_flag_is_accepted_without_starting_client() {
        let args = Cli::try_parse_from([
            "qeli-client",
            "--config",
            "fixture.ini",
            "--print-gateway-owner",
        ])
        .unwrap();
        assert!(args.print_gateway_owner);
        assert_eq!(args.config, PathBuf::from("fixture.ini"));
    }
    #[test]
    fn router_cli_requires_both_expectations_and_metadata_mode() {
        let args = Cli::try_parse_from([
            "qeli-client",
            "--print-gateway-owner",
            "--expect-router-device",
            "vpn0",
            "--expect-router-attach",
            "false",
        ])
        .unwrap();
        assert_eq!(args.expect_router_device.as_deref(), Some("vpn0"));
        assert_eq!(args.expect_router_attach, Some(false));
        for arguments in [
            vec!["qeli-client", "--expect-router-device", "vpn0"],
            vec![
                "qeli-client",
                "--print-gateway-owner",
                "--expect-router-attach",
                "true",
            ],
            vec![
                "qeli-client",
                "--expect-router-device",
                "vpn0",
                "--expect-router-attach",
                "false",
            ],
            vec![
                "qeli-client",
                "--print-gateway-owner",
                "--expect-router-device",
                "vpn0",
                "--expect-router-attach",
                "maybe",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
    }
    #[test]
    fn router_expectation_uses_default_quoted_case_and_canonical_attach() {
        for text in [
            BASE.to_string(),
            format!("{BASE}dev = \"vpn0\"\ndev_attach = \"OFF\"\n"),
            format!(
                "\u{feff}{}DEV = vpn0\nDEV_ATTACH = NO\n",
                BASE.replace("[qeli]", "[QELI]")
            ),
        ] {
            let fixture = Fixture::new(&text);
            assert_eq!(
                qeli::client::inspect_gateway_owner_with_router_expectation(
                    &fixture.0,
                    Some(("vpn0", false))
                )
                .unwrap(),
                "legacy"
            );
        }
    }
    #[test]
    fn router_expectation_rejects_device_attach_and_tap_mismatch() {
        for extra in ["dev = vpn1", "dev_attach = true", "device_type = tap"] {
            let fixture = Fixture::new(&format!("{BASE}{extra}\n"));
            assert!(
                qeli::client::inspect_gateway_owner_with_router_expectation(
                    &fixture.0,
                    Some(("vpn0", false))
                )
                .is_err(),
                "{extra}"
            );
        }
    }
    #[test]
    fn attached_router_requires_ndm_gateway_ownership() {
        let base = format!("{BASE}dev = opkgtun0\ndev_attach = ON\n");
        let fixture = Fixture::new(&base);
        assert_eq!(
            qeli::client::inspect_gateway_owner_with_router_expectation(
                &fixture.0,
                Some(("opkgtun0", true))
            )
            .unwrap(),
            "legacy"
        );
        for key in ["gateway_nat", "forward", "exit_node"] {
            let fixture = Fixture::new(&format!("{base}{key}=true\n"));
            assert!(
                qeli::client::inspect_gateway_owner_with_router_expectation(
                    &fixture.0,
                    Some(("opkgtun0", true))
                )
                .is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn all_core_gateway_flags_suppress_legacy_ownership() {
        for key in ["gateway_nat", "forward", "exit_node"] {
            assert_eq!(
                Fixture::new(&format!("{BASE}{key}=true\n"))
                    .owner()
                    .unwrap(),
                "core",
                "{key}"
            );
        }
    }
    #[test]
    fn quoted_uppercase_bom_and_on_values_use_canonical_parser() {
        for value in ["true", "TRUE", "on", "YES", "1", "\"TrUe\"", "\"ON\""] {
            let text = format!(
                "\u{feff}{}{value}\n",
                BASE.replace("[qeli]", "[QELI]") + "GATEWAY_NAT = "
            );
            assert_eq!(Fixture::new(&text).owner().unwrap(), "core", "{value}");
        }
    }
    #[test]
    fn absent_and_false_flags_keep_explicit_legacy_fallback() {
        assert_eq!(Fixture::new(BASE).owner().unwrap(), "legacy");
        for value in ["false", "OFF", "0", "\"No\""] {
            assert_eq!(
                Fixture::new(&format!("{BASE}gateway_nat={value}\n"))
                    .owner()
                    .unwrap(),
                "legacy"
            );
        }
    }
    #[test]
    fn invalid_bool_unknown_duplicate_and_conflicting_flags_reject() {
        for extra in [
            "gateway_nat=maybe",
            "gateway_nat=true\ngateway_nat=false",
            "unknown_option=true",
            "exit_node=true\nforward=true",
        ] {
            assert!(
                Fixture::new(&format!("{BASE}{extra}\n")).owner().is_err(),
                "{extra}"
            );
        }
    }
    #[test]
    fn file_hooks_are_never_executed_by_inspection() {
        let marker = Fixture::new("");
        std::fs::remove_file(&marker.0).unwrap();
        let config = Fixture::new(&format!("{BASE}post_up=touch {}\n", marker.0.display()));
        assert_eq!(config.owner().unwrap(), "legacy");
        assert!(!marker.0.exists());
    }
    #[test]
    fn missing_file_and_nonregular_directory_reject() {
        let fixture = Fixture::new(BASE);
        std::fs::remove_file(&fixture.0).unwrap();
        assert!(fixture.owner().is_err());
        assert!(qeli::client::inspect_gateway_owner(&std::env::temp_dir()).is_err());
    }
    #[test]
    fn oversized_file_is_rejected_by_shared_bound() {
        let fixture = Fixture::new("");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.0)
            .unwrap()
            .set_len(qeli::transport_core::MAX_CONFIG_BYTES as u64 + 1)
            .unwrap();
        assert!(fixture.owner().is_err());
    }
}
