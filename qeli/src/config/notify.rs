//! Notification settings use the shared INI grammar. Persisted configuration is INI only.
use super::format::{IniDoc, Section};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Which events a single channel sends. Defaults to all-on, so a freshly enabled
/// channel notifies everything until the admin trims it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelEvents {
    #[serde(default = "d_true")]
    pub on_server_start: bool,
    #[serde(default = "d_true")]
    pub on_quota_breach: bool,
    #[serde(default = "d_true")]
    pub on_login_lockout: bool,
    #[serde(default = "d_true")]
    pub on_auth_lockout: bool,
    #[serde(default = "d_true")]
    pub on_restore: bool,
    /// Client connect/disconnect can be high-volume, so these default OFF (opt-in)
    /// unlike the rare security/lifecycle events above.
    #[serde(default)]
    pub on_client_connect: bool,
    #[serde(default)]
    pub on_client_disconnect: bool,
}

impl Default for ChannelEvents {
    fn default() -> Self {
        Self {
            on_server_start: true,
            on_quota_breach: true,
            on_login_lockout: true,
            on_auth_lockout: true,
            on_restore: true,
            on_client_connect: false,
            on_client_disconnect: false,
        }
    }
}

/// Telegram and the generic webhook are fully independent channels — each has its
/// own enable switch, credentials, and event selection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    /// Optional label identifying THIS server in notification messages, so several
    /// servers reporting to the same Telegram chat / webhook are distinguishable.
    /// Empty = omit. Set it here in `/etc/qeli/notify.ini` or on the panel's
    /// Notifications page.
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub telegram_enabled: bool,
    #[serde(default)]
    pub telegram_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,
    #[serde(default)]
    pub telegram_events: ChannelEvents,
    #[serde(default)]
    pub webhook_enabled: bool,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub webhook_events: ChannelEvents,
}

fn d_true() -> bool {
    true
}

impl ChannelEvents {
    fn read(&mut self, section: &Section) {
        self.on_server_start = section.bool_or("on_server_start", self.on_server_start);
        self.on_quota_breach = section.bool_or("on_quota_breach", self.on_quota_breach);
        self.on_login_lockout = section.bool_or("on_login_lockout", self.on_login_lockout);
        self.on_auth_lockout = section.bool_or("on_auth_lockout", self.on_auth_lockout);
        self.on_restore = section.bool_or("on_restore", self.on_restore);
        self.on_client_connect = section.bool_or("on_client_connect", self.on_client_connect);
        self.on_client_disconnect =
            section.bool_or("on_client_disconnect", self.on_client_disconnect);
    }
    fn write(&self, section: &mut Section) {
        section.set("on_server_start", self.on_server_start.to_string());
        section.set("on_quota_breach", self.on_quota_breach.to_string());
        section.set("on_login_lockout", self.on_login_lockout.to_string());
        section.set("on_auth_lockout", self.on_auth_lockout.to_string());
        section.set("on_restore", self.on_restore.to_string());
        section.set("on_client_connect", self.on_client_connect.to_string());
        section.set(
            "on_client_disconnect",
            self.on_client_disconnect.to_string(),
        );
    }
}

impl NotifyConfig {
    pub fn from_ini(raw: &str) -> anyhow::Result<Self> {
        let doc = IniDoc::parse(raw)?;
        if doc.sections.is_empty() {
            anyhow::bail!("notification config requires an INI section");
        }
        let mut seen = std::collections::HashSet::new();
        let mut config = Self::default();
        for section in &doc.sections {
            if section.instance.is_some() || !seen.insert(section.kind.as_str()) {
                anyhow::bail!(
                    "invalid or duplicate notification section {}",
                    section.header()
                );
            }
            match section.kind.as_str() {
                "notify" => config.server_name = section.str_or("server_name", "").to_string(),
                "telegram" => {
                    config.telegram_enabled = section.bool_or("enabled", false);
                    config.telegram_token = section.str_or("token", "").to_string();
                    config.telegram_chat_id = section.str_or("chat_id", "").to_string();
                    config.telegram_events.read(section);
                }
                "webhook" => {
                    config.webhook_enabled = section.bool_or("enabled", false);
                    config.webhook_url = section.str_or("url", "").to_string();
                    config.webhook_events.read(section);
                }
                _ => anyhow::bail!("unknown notification section {}", section.header()),
            }
        }
        let unknown = doc.unread_keys();
        if !unknown.is_empty() {
            anyhow::bail!("unknown notification setting(s): {:?}", unknown);
        }
        let bad = doc.bad_values();
        if !bad.is_empty() {
            anyhow::bail!("invalid notification setting(s): {}", bad.join("; "));
        }
        Ok(config)
    }

    pub fn to_ini_string(&self) -> anyhow::Result<String> {
        let mut doc = IniDoc::new();
        let mut general = Section::new("notify", None);
        general.set("server_name", &self.server_name);
        doc.push(general);
        let mut telegram = Section::new("telegram", None);
        telegram.set("enabled", self.telegram_enabled.to_string());
        telegram.set("token", &self.telegram_token);
        telegram.set("chat_id", &self.telegram_chat_id);
        self.telegram_events.write(&mut telegram);
        doc.push(telegram);
        let mut webhook = Section::new("webhook", None);
        webhook.set("enabled", self.webhook_enabled.to_string());
        webhook.set("url", &self.webhook_url);
        self.webhook_events.write(&mut webhook);
        doc.push(webhook);
        let raw = doc.to_string();
        if Self::from_ini(&raw)? != *self {
            anyhow::bail!("notification settings contain unsupported control characters");
        }
        Ok(raw)
    }
}

static IO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Notification settings are small. Refuse oversized or non-regular INI files before
/// parsing, and do not silently replace an old JSON-only installation with defaults.
pub const MAX_NOTIFY_INI_BYTES: u64 = 64 * 1024;

fn load_path_unlocked(path: &Path) -> anyhow::Result<(NotifyConfig, String)> {
    match crate::config_source::load_bounded(path, MAX_NOTIFY_INI_BYTES) {
        Ok(snapshot) => {
            let (raw, trust) = snapshot.into_parts();
            // Outbound destinations and credentials are privileged configuration.
            // Never let a panel save upgrade the trust of attacker-writable bytes.
            #[cfg(unix)]
            trust
                .check()
                .map_err(|reason| anyhow::anyhow!("untrusted notification INI: {reason}"))?;
            #[cfg(not(unix))]
            let _ = trust;
            let config = NotifyConfig::from_ini(&raw)?;
            Ok((config, raw))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let legacy = path.with_extension("json");
            if legacy.try_exists()? {
                anyhow::bail!(
                    "unsupported legacy notification config '{}'; convert it to INI before starting notifications",
                    legacy.display()
                );
            }
            Ok((NotifyConfig::default(), String::new()))
        }
        Err(error) => Err(error.into()),
    }
}

/// Return parsed settings and the exact INI bytes from one stable file snapshot.
pub fn load_path_with_raw(path: &Path) -> anyhow::Result<(NotifyConfig, String)> {
    let _guard = IO_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    load_path_unlocked(path)
}

pub fn load_path(path: &Path) -> anyhow::Result<NotifyConfig> {
    load_path_with_raw(path).map(|(config, _)| config)
}

fn bounded_ini(config: &NotifyConfig) -> anyhow::Result<String> {
    let raw = config.to_ini_string()?;
    anyhow::ensure!(
        raw.len() as u64 <= MAX_NOTIFY_INI_BYTES,
        "notification INI is {} bytes; maximum is {MAX_NOTIFY_INI_BYTES}",
        raw.len()
    );
    Ok(raw)
}

pub fn save_path(path: &Path, config: &NotifyConfig) -> anyhow::Result<()> {
    let raw = bounded_ini(config)?;
    let _guard = IO_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    #[cfg(unix)]
    let _file_lock = crate::util::FileLock::acquire(path)?;
    crate::util::write_atomic_private(path, raw.as_bytes())
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConditionalSave {
    Saved(String),
    Conflict(String),
}

/// Serialize panel writers and compare exact bytes again immediately before publication.
/// A non-cooperating external editor can still race the final rename.
pub fn save_path_if_unchanged(
    path: &Path,
    config: &NotifyConfig,
    checked_raw: &str,
) -> anyhow::Result<ConditionalSave> {
    let raw = bounded_ini(config)?;
    let _guard = IO_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    #[cfg(unix)]
    let _file_lock = crate::util::FileLock::acquire(path)?;
    let (_, current_raw) = load_path_unlocked(path)?;
    if current_raw != checked_raw {
        return Ok(ConditionalSave::Conflict(current_raw));
    }
    crate::util::write_atomic_private(path, raw.as_bytes())?;
    Ok(ConditionalSave::Saved(raw))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> NotifyConfig {
        NotifyConfig {
            server_name: " \"edge\"; # ".into(),
            telegram_enabled: true,
            telegram_token: "\tfixture-token\t".into(),
            telegram_chat_id: "-100123".into(),
            telegram_events: ChannelEvents {
                on_client_connect: true,
                on_auth_lockout: false,
                ..Default::default()
            },
            webhook_enabled: true,
            webhook_url: "https://fixture.invalid/path?a=b#test".into(),
            webhook_events: ChannelEvents {
                on_restore: false,
                ..Default::default()
            },
        }
    }
    fn directory(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("qeli-notify-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    #[test]
    fn settings_and_secrets_survive_ini_roundtrip() {
        let config = fixture();
        let raw = config.to_ini_string().unwrap();
        assert_eq!(NotifyConfig::from_ini(&raw).unwrap(), config);
        assert!(raw.starts_with("[notify]"));
        assert!(NotifyConfig {
            server_name: "line\nbreak".into(),
            ..config
        }
        .to_ini_string()
        .is_err());
    }
    #[test]
    fn ambiguous_notification_settings_are_rejected() {
        for raw in [
            "",
            "[telegram]\nenabled=maybe",
            "[telegram]\nenabled=true\nenabled=false",
            "[telegram]\n[ telegram ]",
            "[telegram]\ntkoen=x",
            "[other]",
            "[webhook:named]\nenabled=true",
        ] {
            assert!(NotifyConfig::from_ini(raw).is_err(), "{raw:?}");
        }
        assert!(
            NotifyConfig::from_ini("[telegram]\nenabled=ON")
                .unwrap()
                .telegram_enabled
        );
    }
    #[test]
    fn ini_only_loader_refuses_legacy_file_without_rewriting_it() {
        let dir = directory("ini-only");
        let ini = dir.join("notify.ini");
        let old = dir.join("notify.json");
        std::fs::write(&old, b"legacy secret").unwrap();
        let error = load_path(&ini).unwrap_err().to_string();
        assert!(
            error.contains("unsupported legacy notification config"),
            "{error}"
        );
        assert!(!ini.exists());
        assert_eq!(std::fs::read(&old).unwrap(), b"legacy secret");

        let config = fixture();
        save_path(&ini, &config).unwrap();
        assert_eq!(load_path(&ini).unwrap(), config);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&ini).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(&ini).unwrap();
        std::fs::remove_file(&old).unwrap();
        assert_eq!(load_path(&ini).unwrap(), NotifyConfig::default());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn untrusted_sidecar_cannot_send_or_be_authorized_by_panel_save() {
        use std::os::unix::{fs::symlink, fs::PermissionsExt};
        let dir = directory("trust");
        let ini = dir.join("notify.ini");
        let cfg = fixture();
        let raw = cfg.to_ini_string().unwrap();
        std::fs::write(&ini, &raw).unwrap();
        std::fs::set_permissions(&ini, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_path(&ini)
            .unwrap_err()
            .to_string()
            .contains("untrusted"));
        assert!(save_path_if_unchanged(&ini, &cfg, &raw).is_err());
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), raw);
        assert_eq!(
            std::fs::metadata(&ini).unwrap().permissions().mode() & 0o777,
            0o666
        );
        std::fs::set_permissions(&ini, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_path(&ini).unwrap(), cfg);
        let link = dir.join("linked.ini");
        symlink(&ini, &link).unwrap();
        assert!(load_path(&link)
            .unwrap_err()
            .to_string()
            .contains("symlink"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn conditional_save_rejects_stale_tab_and_manual_ini_edit() {
        let dir = directory("revision");
        let ini = dir.join("notify.ini");
        let (mut config, initial_raw) = load_path_with_raw(&ini).unwrap();
        assert!(initial_raw.is_empty());
        config.server_name = "first".into();
        let saved_raw = match save_path_if_unchanged(&ini, &config, &initial_raw).unwrap() {
            ConditionalSave::Saved(raw) => raw,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), saved_raw);

        config.server_name = "stale".into();
        assert_eq!(
            save_path_if_unchanged(&ini, &config, &initial_raw).unwrap(),
            ConditionalSave::Conflict(saved_raw.clone())
        );
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), saved_raw);

        let edited_raw = format!("# manual edit\n{saved_raw}");
        std::fs::write(&ini, &edited_raw).unwrap();
        assert_eq!(
            save_path_if_unchanged(&ini, &config, &saved_raw).unwrap(),
            ConditionalSave::Conflict(edited_raw.clone())
        );
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), edited_raw);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn invalid_or_oversized_ini_is_rejected_without_overwriting() {
        let dir = directory("bounded");
        let ini = dir.join("notify.ini");
        std::fs::write(&ini, "[telegram]\nenabled=bad").unwrap();
        assert!(load_path(&ini).is_err());

        std::fs::write(&ini, "#".repeat(MAX_NOTIFY_INI_BYTES as usize + 1)).unwrap();
        let error = load_path(&ini).unwrap_err().to_string();
        assert!(error.contains("maximum is 65536"), "{error}");
        let oversized = NotifyConfig {
            server_name: "x".repeat(MAX_NOTIFY_INI_BYTES as usize),
            ..Default::default()
        };
        assert!(save_path(&ini, &oversized).is_err());
        assert_eq!(
            std::fs::metadata(&ini).unwrap().len(),
            MAX_NOTIFY_INI_BYTES + 1
        );

        std::fs::remove_file(&ini).unwrap();
        std::fs::create_dir(&ini).unwrap();
        assert!(load_path(&ini).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
