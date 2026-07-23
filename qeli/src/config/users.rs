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
    /// Never sent over the JSON API (`/api/users`, `/api/config`) — same treatment as
    /// `password_enc`. The users file is written by the hand-rolled INI codec, not serde,
    /// so skipping serialization does NOT drop the hash from disk.
    /// `default` is REQUIRED alongside `skip_serializing`: the field is dropped from every
    /// API response, so without a default the round-trip (GET a user → POST it back to
    /// create/edit a profile) fails to deserialize with "missing field password_hash"
    /// (issue #69). The real hash is preserved from disk by the INI codec, not this path.
    #[serde(default, skip_serializing)]
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
    /// Подсети/адреса, которые находятся ЗА этим клиентом (его собственный доп.
    /// адрес или LAN, если клиент — шлюз). Сервер маршрутизирует ВХОДЯЩИЙ трафик на
    /// эти адреса в туннель ЭТОГО клиента (аналог OpenVPN `iroute`). В отличие от
    /// `routes` (которые ПУШатся клиенту, чтобы он заворачивал их в туннель), это —
    /// серверная inbound-регистрация: без неё сервер знает лишь пуловый IP клиента и
    /// дропает пакеты на любой другой его адрес (#13). Список CIDR/IP.
    #[serde(default)]
    pub client_subnets: Vec<String>,
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
        if username.is_empty() {
            return None;
        }
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
        crate::util::write_atomic_private(path, self.to_ini_string().as_bytes())
    }

    /// Apply one change to the users file as a cross-process read-modify-write.
    ///
    /// `save` writes the caller's WHOLE in-memory database, which is only correct when
    /// that copy is current. Three processes hold their own copy — the supervisor (panel
    /// CRUD), the worker (control socket: bandwidth, quota, kick…) and the CLI
    /// (`add-client`) — and none of them re-read before writing, so the last writer
    /// silently reverted everyone else. A single panel edit that changed a password AND
    /// the bandwidth limit did it to itself: the supervisor wrote the new password, then
    /// asked the worker to set the limit, and the worker saved its pre-edit snapshot back
    /// over it. (Observed in the lab as a user added by `add-client` vanishing minutes
    /// later, overwritten by the running worker.)
    ///
    /// So: take an exclusive lock, re-read the file, apply the change to THAT, write, and
    /// hand the fresh database back so the caller can refresh its own copy. The lock is a
    /// sidecar file rather than the users file itself, because `save` replaces the inode
    /// (temp + rename) — a lock held on the old inode would guard nothing.
    pub fn update_locked<R>(
        path: impl AsRef<Path>,
        change: impl FnOnce(&mut UsersDb) -> R,
    ) -> anyhow::Result<(Self, R)> {
        let path = path.as_ref();
        let _lock = crate::util::FileLock::acquire(path)?;
        // A MISSING file = first write (e.g. `add-client` on a fresh install) → start
        // empty. But a CORRUPT / unreadable / unparseable file must NOT collapse to an
        // empty DB, because the `save()` below would then persist that empty DB over the
        // real users file — wiping every account. Distinguish NotFound (ok → default)
        // from any other read/parse error (abort the write, leave the file untouched).
        let mut db = match std::fs::read_to_string(path) {
            Ok(content) => {
                let doc = crate::config::format::IniDoc::parse(&content).map_err(|e| {
                    anyhow::anyhow!(
                        "refusing to modify the users DB: '{}' is present but unparseable ({e}) \
                         — not overwriting it with an empty database",
                        path.display()
                    )
                })?;
                UsersDb::from_ini(&doc)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => UsersDb::default(),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "refusing to modify the users DB: cannot read '{}' ({e}) — not \
                     overwriting it with an empty database",
                    path.display()
                ));
            }
        };
        let out = change(&mut db);
        db.save(path)?;
        Ok((db, out))
    }
}

impl UsersDb {
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

    fn tmp_users(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!("qeli-users-test-{tag}.conf"));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{}.lock", p.display()));
        p.to_string_lossy().into_owned()
    }

    fn named(n: &str) -> UserEntry {
        UserEntry {
            username: n.to_string(),
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_stale_copy_cannot_revert_another_writers_change() {
        // The real-world shape of the bug: three processes each keep their own copy of
        // the database and used to write the WHOLE thing back, so whoever saved last
        // reverted the others. Here "the other process" adds bob while we hold a copy
        // that predates him.
        let path = tmp_users("lostupdate");
        UsersDb::update_locked(&path, |db| db.users.push(named("alice"))).unwrap();
        let stale = UsersDb::load(&path).unwrap();
        UsersDb::update_locked(&path, |db| db.users.push(named("bob"))).unwrap();

        // Our copy never heard of bob — writing it back verbatim is what lost him.
        assert!(stale.users.iter().all(|u| u.username != "bob"));

        // Going through update_locked re-reads first, so our change lands ON TOP of his.
        let (fresh, found) =
            UsersDb::update_locked(&path, |db| db.set_bandwidth("alice", 5)).unwrap();
        assert!(found, "alice must still be there to modify");
        let names: Vec<&str> = fresh.users.iter().map(|u| u.username.as_str()).collect();
        assert!(
            names.contains(&"alice") && names.contains(&"bob"),
            "both writers survive: {names:?}"
        );

        // And it is on disk, not just in the returned copy.
        let on_disk = UsersDb::load(&path).unwrap();
        assert_eq!(on_disk.users.len(), 2);
        assert_eq!(
            on_disk
                .users
                .iter()
                .find(|u| u.username == "alice")
                .unwrap()
                .bandwidth
                .limit_mbps,
            5
        );
    }
}
