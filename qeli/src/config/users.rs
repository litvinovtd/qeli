use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct UsersDb {
    #[serde(default)]
    pub users: Vec<UserEntry>,
    #[serde(default)]
    pub groups: HashMap<String, GroupTemplate>,
}

/// Маршрут, задаваемый конкретному пользователю.
/// Если routes пуст — используются глобальные advertised_routes сервера.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct UserRoute {
    pub cidr: String,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub metric: Option<u32>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct UserEntry {
    // Scalar / scalar-array fields first, then sub-tables (bandwidth, metadata,
    // routes) — required so the struct serializes to valid TOML.
    pub username: String,
    pub password_hash: String,
    /// Reversibly-encrypted copy of the plaintext password (base64, ChaCha20-
    /// Poly1305 under the panel key) so the admin can re-issue a `qeli://`
    /// config/QR without knowing the password. `None` for legacy/hash-only users
    /// — re-issue then needs a one-time reset. Never sent over the API
    /// (`skip_serializing`); persisted only in the users file via the INI codec.
    #[serde(default, skip_serializing)]
    pub password_enc: Option<String>,
    pub static_ip: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_networks: Vec<String>,
    #[serde(default)]
    pub group: Option<String>,
    /// Максимальное кол-во одновременных сессий (0 = из группы или дефолт)
    #[serde(default)]
    pub max_sessions: u32,
    /// Lifetime data cap in GB (0 = unlimited). Server-side only: enforced at auth
    /// and by the usage sweep (over-quota live sessions are disconnected like a
    /// kick). Consumption is tracked in the `usage.json` sidecar, not here.
    #[serde(default)]
    pub data_limit_gb: u64,
    /// Account expiry as a Unix timestamp in seconds; `None` = never expires. Past
    /// it the user is rejected at auth and disconnected by the sweep. Server-side
    /// only — no wire/protocol change, so clients need no update.
    #[serde(default)]
    pub expire_at: Option<i64>,
    /// Профили (интерфейсы), к которым пользователю разрешено подключаться.
    /// Пусто — разрешены все профили; иначе только перечисленные. Так один
    /// интерфейс изолируется от другого: юзер с `["tcp"]` не войдёт на `udp`.
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub bandwidth: BandwidthLimit,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Индивидуальные маршруты для этого пользователя.
    /// Если задан — переопределяет глобальные advertised_routes.
    #[serde(default)]
    pub routes: Vec<UserRoute>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct BandwidthLimit {
    #[serde(default)]
    pub limit_mbps: u32,
    #[serde(default)]
    pub burst_mbps: u32,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct GroupTemplate {
    pub bandwidth_limit_mbps: Option<u32>,
    pub max_sessions: Option<u32>,
    pub allowed_networks: Option<Vec<String>>,
}

impl UsersDb {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        // The users file is flat INI: `[user:<name>]` / `[group:<name>]`.
        let doc = crate::config::format::IniDoc::parse(&content)?;
        Ok(UsersDb::from_ini(&doc))
    }

    pub fn find_user(&self, username: &str) -> Option<&UserEntry> {
        self.users
            .iter()
            .find(|u| u.username == username && u.enabled)
    }

    /// Сохранить текущее состояние БД обратно в файл (для runtime-изменений).
    /// Пишется в flat-INI (единый формат с остальными конфигами).
    ///
    /// Запись атомарна (temp+rename): этот файл хранит ВСЕ хэши паролей и
    /// перезаписывается на каждый CRUD из панели, поэтому обрыв на середине
    /// `std::fs::write` мог оставить усечённый/битый файл и заблокировать вход
    /// всем. `write_atomic` сохраняет права исходного файла (0600 не расширяется).
    pub fn save(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        crate::util::write_atomic(path, self.to_ini_string().as_bytes())
    }

    /// Обновить лимит bandwidth для пользователя и вернуть Ok если нашли.
    pub fn set_bandwidth(&mut self, username: &str, mbps: u32) -> bool {
        if let Some(user) = self.users.iter_mut().find(|u| u.username == username) {
            user.bandwidth.limit_mbps = mbps;
            user.bandwidth.burst_mbps = mbps.saturating_add(mbps / 4);
            return true;
        }
        false
    }
}

fn default_enabled() -> bool {
    true
}

impl UserEntry {
    /// Whether this user may connect to the given profile (interface).
    /// An empty `profiles` list means "all profiles" (unrestricted).
    pub fn allowed_on_profile(&self, profile: &str) -> bool {
        self.profiles.is_empty() || self.profiles.iter().any(|p| p == profile)
    }

    pub fn effective_bandwidth_limit(&self, groups: &HashMap<String, GroupTemplate>) -> u32 {
        if self.bandwidth.limit_mbps > 0 {
            return self.bandwidth.limit_mbps;
        }
        if let Some(ref group_name) = self.group {
            if let Some(group) = groups.get(group_name) {
                if let Some(limit) = group.bandwidth_limit_mbps {
                    return limit;
                }
            }
        }
        0
    }

    /// Максимум одновременных сессий (распознанных устройств) этого юзера: своё
    /// значение, иначе из группы, иначе `0` = без лимита. Считается по device_key,
    /// так что реконнект устройства не тратит слот (вытесняет свою же сессию).
    pub fn effective_max_sessions(&self, groups: &HashMap<String, GroupTemplate>) -> u32 {
        if self.max_sessions > 0 {
            return self.max_sessions;
        }
        if let Some(ref group_name) = self.group {
            if let Some(group) = groups.get(group_name) {
                if let Some(limit) = group.max_sessions {
                    return limit;
                }
            }
        }
        0
    }
}

#[cfg(test)]
mod max_sessions_tests {
    use super::*;

    fn groups(name: &str, cap: Option<u32>) -> HashMap<String, GroupTemplate> {
        let mut g = HashMap::new();
        g.insert(
            name.to_string(),
            GroupTemplate {
                bandwidth_limit_mbps: None,
                max_sessions: cap,
                allowed_networks: None,
            },
        );
        g
    }

    #[test]
    fn own_value_wins() {
        let u = UserEntry {
            max_sessions: 3,
            group: Some("staff".into()),
            ..Default::default()
        };
        assert_eq!(u.effective_max_sessions(&groups("staff", Some(5))), 3);
    }

    #[test]
    fn falls_back_to_group() {
        let u = UserEntry {
            max_sessions: 0,
            group: Some("staff".into()),
            ..Default::default()
        };
        assert_eq!(u.effective_max_sessions(&groups("staff", Some(5))), 5);
    }

    #[test]
    fn zero_everywhere_is_unlimited() {
        let u = UserEntry {
            max_sessions: 0,
            group: None,
            ..Default::default()
        };
        assert_eq!(u.effective_max_sessions(&HashMap::new()), 0);
    }
}
