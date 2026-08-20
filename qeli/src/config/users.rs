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
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
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
    /// Fixed address from the profile's legacy IPv4 pool.
    pub static_ip: Option<String>,
    /// Fixed address from the profile's IPv6 pool. Kept separate so old IPv4-only clients and
    /// profiles retain their exact allocation behavior.
    #[serde(default)]
    pub static_ipv6: Option<String>,
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

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
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

/// Validate an IPv4 allow-list in the same form accepted by the data plane:
/// CIDR notation or a bare address (treated as /32).  This lives in the config
/// layer rather than the panel so file-based, inline and restored users receive
/// the same fail-closed validation.
pub fn validate_allowed_networks(nets: &[String], owner: &str) -> Result<(), String> {
    for raw in nets {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        let valid = match value.split_once('/') {
            Some((address, prefix)) => {
                address.trim().parse::<std::net::Ipv4Addr>().is_ok()
                    && prefix.trim().parse::<u8>().is_ok_and(|length| length <= 32)
            }
            None => value.parse::<std::net::Ipv4Addr>().is_ok(),
        };
        if !valid {
            return Err(format!(
                "{owner}: allowed_networks entry {value:?} is not a valid IPv4 CIDR or address"
            ));
        }
    }
    Ok(())
}

/// Refuse a users file containing a key nothing read — i.e. a misspelling.
///
/// `bad_values()` catches a bad VALUE under a correct key (`max_sessions = ten`); this catches
/// a correct value under a MISSPELLED key (`max_session = 1`), which is the more dangerous
/// half and was left open. Nothing reads the typo, so the real `max_sessions` stays 0 — and 0
/// on this file does not mean "default", it means NO LIMIT. The restriction the operator wrote
/// simply is not there, and the file still looks like it says so.
///
/// It also compounds: the typo is invisible to the INI codec that rewrites the file, so the
/// next panel edit or `add-client` drops the line entirely and the evidence disappears.
///
/// `IniDoc` has tracked this since the `exclude_routes` bug — the mechanism existed and this
/// file just never asked. Must be called AFTER `from_ini`, or every key looks unread.
/// (Audit 2026-08-02, follow-up.)
fn reject_unread_keys(doc: &crate::config::format::IniDoc, path: &Path) -> anyhow::Result<()> {
    let unread = doc.unread_keys();
    if unread.is_empty() {
        return Ok(());
    }
    let listed: Vec<String> = unread
        .iter()
        .map(|(section, key)| format!("{section} {key}"))
        .collect();
    anyhow::bail!(
        "{} unrecognised key(s) in the users database '{}' — nothing reads these, so the \
         setting each was meant to impose is absent (and a missing limit means NO limit):\n  {}",
        listed.len(),
        path.display(),
        listed.join("\n  ")
    )
}

impl UsersDb {
    /// Validate access-control values that cannot be represented by the INI
    /// parser's scalar type checks. A typo here must refuse the database rather
    /// than reach the runtime's deny-all fallback and unexpectedly lock a user out.
    pub fn validate_access_controls(&self) -> anyhow::Result<()> {
        for user in &self.users {
            validate_allowed_networks(&user.allowed_networks, &format!("user {:?}", user.username))
                .map_err(anyhow::Error::msg)?;
        }
        for (name, group) in &self.groups {
            if let Some(networks) = &group.allowed_networks {
                validate_allowed_networks(networks, &format!("group {name:?}"))
                    .map_err(anyhow::Error::msg)?;
            }
        }
        Ok(())
    }

    /// Parse and validate a users database already held in memory.  Restore uses
    /// this before publishing staged bytes; ordinary callers normally use
    /// [`UsersDb::load`].
    pub fn parse_strict(content: &str, source: impl AsRef<Path>) -> anyhow::Result<Self> {
        // The users file is flat INI: `[user:<name>]` / `[group:<name>]`.
        let doc = crate::config::format::IniDoc::parse(content)?;
        let db = UsersDb::from_ini(&doc);
        // Values that were PRESENT but unreadable are refused here, not shrugged off.
        //
        // This file is the access-control list, and its numbers are LIMITS whose disabled
        // value is zero: `max_sessions = ten` and `data_limit_gb = 50G` both fall back to 0,
        // which does not mean "default" — it means NO LIMIT. So a typo quietly removes the
        // very restriction it was written to impose, on the one file where that matters most.
        // The findings were already recorded by `parse_or`; nothing looked at them.
        // (Audit 2026-08-02, §5.)
        let bad = doc.bad_values();
        if !bad.is_empty() {
            anyhow::bail!(
                "{} unreadable value(s) in the users database — limits would silently become \
                 unlimited:\n  {}",
                bad.len(),
                bad.join("\n  ")
            );
        }
        reject_unread_keys(&doc, source.as_ref())?;
        db.validate_network_fields()?;
        Ok(db)
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        Self::parse_strict(&content, path)
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
        self.validate_network_fields()?;
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
                // The WRITE path must be at least as strict as the load path.
                //
                // `load()` refuses a file with unreadable values, because a limit that will
                // not parse falls back to 0 and 0 means NO LIMIT. This path only checked that
                // the file was syntactically parseable — so a file the server would refuse to
                // start on could still be opened here through the panel or `add-client`,
                // silently converted (`max_sessions = ten` → 0), and then written BACK by the
                // `save()` below. The unreadable value would be gone from the file and the
                // restriction gone with it, having passed through the one code path that
                // holds the write lock. A read-only refusal on one side and a rewrite on the
                // other is worse than either being lenient. (Audit 2026-08-02, §3 of the
                // follow-up.)
                // ORDER MATTERS, and getting it wrong makes both checks silently vacuous:
                // `bad_values` and the read-tracking behind `unread_keys` are populated BY the
                // readers inside `from_ini`, so asking a freshly-parsed document reports
                // nothing at all. The load path above has always done this correctly; this one
                // asked first and answered into the void, which is worse than not checking —
                // it looks checked.
                let db = UsersDb::from_ini(&doc);
                let bad = doc.bad_values();
                if !bad.is_empty() {
                    anyhow::bail!(
                        "refusing to modify the users DB: '{}' has {} unreadable value(s), and \
                         saving would replace them with defaults that mean NO LIMIT:\n  {}",
                        path.display(),
                        bad.len(),
                        bad.join("\n  ")
                    );
                }
                // Same reasoning as the value check above, and the same reason it belongs on
                // the WRITE path too: a misspelled key is invisible to the codec that rewrites
                // this file, so saving would drop the line and take the operator's last clue
                // with it.
                reject_unread_keys(&doc, path)?;
                db.validate_network_fields()?;
                db
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
        db.validate_access_controls()?;
        let out = change(&mut db);
        db.validate_network_fields()?;
        db.save(path)?;
        Ok((db, out))
    }

    /// Validate the network policy stored in the user database. These values control source
    /// authorization and routing, so silently ignoring a malformed family or prefix would be
    /// fail-open.
    pub fn validate_network_fields(&self) -> anyhow::Result<()> {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        fn network_family(value: &str) -> Option<bool> {
            let address = value
                .split_once('/')
                .map_or(value, |(address, _)| address)
                .trim()
                .parse::<IpAddr>()
                .ok()?;
            Some(address.is_ipv6())
        }

        fn validate_network_list(
            username: &str,
            field: &str,
            values: &[String],
        ) -> anyhow::Result<()> {
            for raw in values {
                let value = raw.trim();
                if value.is_empty() {
                    continue;
                }
                if !crate::util::is_valid_cidr(value) && value.parse::<IpAddr>().is_err() {
                    anyhow::bail!(
                        "user '{}': {} entry '{}' is not a valid IPv4/IPv6 CIDR or address",
                        username,
                        field,
                        value
                    );
                }
            }
            Ok(())
        }

        let mut static_ipv4_owners: HashMap<Ipv4Addr, &str> = HashMap::new();
        let mut static_ipv6_owners: HashMap<Ipv6Addr, &str> = HashMap::new();

        for user in &self.users {
            if let Some(raw) = user.static_ip.as_deref() {
                let value = raw.trim();
                let address = value.parse::<Ipv4Addr>().map_err(|error| {
                    anyhow::anyhow!(
                        "user '{}': static_ip '{}' is not a bare IPv4 address: {}",
                        user.username,
                        value,
                        error
                    )
                })?;
                if let Some(owner) = static_ipv4_owners.insert(address, &user.username) {
                    anyhow::bail!(
                        "users '{}' and '{}' have the same static_ip '{}'",
                        owner,
                        user.username,
                        address
                    );
                }
            }
            if let Some(raw) = user.static_ipv6.as_deref() {
                let value = raw.trim();
                let address = value.parse::<Ipv6Addr>().map_err(|error| {
                    anyhow::anyhow!(
                        "user '{}': static_ipv6 '{}' is not a bare IPv6 address: {}",
                        user.username,
                        value,
                        error
                    )
                })?;
                crate::config::server::validate_tunnel_ipv6_address("static_ipv6", address)
                    .map_err(|error| anyhow::anyhow!("user '{}': {}", user.username, error))?;
                if let Some(owner) = static_ipv6_owners.insert(address, &user.username) {
                    anyhow::bail!(
                        "users '{}' and '{}' have the same static_ipv6 '{}'",
                        owner,
                        user.username,
                        address
                    );
                }
            }

            validate_network_list(&user.username, "allowed_networks", &user.allowed_networks)?;
            validate_network_list(&user.username, "client_subnet", &user.client_subnets)?;
            for route in &user.routes {
                if !crate::util::is_valid_cidr(&route.cidr) {
                    anyhow::bail!(
                        "user '{}': route CIDR '{}' is invalid",
                        user.username,
                        route.cidr
                    );
                }
                if let Some(gateway) = route.gateway.as_deref() {
                    let gateway = gateway.trim();
                    let gateway_ip = gateway.parse::<IpAddr>().map_err(|error| {
                        anyhow::anyhow!(
                            "user '{}': route gateway '{}' is not a bare IP address: {}",
                            user.username,
                            gateway,
                            error
                        )
                    })?;
                    if network_family(&route.cidr) != Some(gateway_ip.is_ipv6()) {
                        anyhow::bail!(
                            "user '{}': route '{}' and gateway '{}' use different address families",
                            user.username,
                            route.cidr,
                            gateway
                        );
                    }
                }
            }
        }
        for (group, template) in &self.groups {
            if let Some(networks) = &template.allowed_networks {
                validate_network_list(&format!("group:{group}"), "allowed_networks", networks)?;
            }
        }
        Ok(())
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
mod load_tests {
    use super::*;

    #[test]
    fn ipv4_and_ipv6_user_network_policy_validates_together() {
        let mut user = UserEntry {
            username: "alice".into(),
            static_ip: Some("10.9.0.50".into()),
            static_ipv6: Some("fd71:e1:1234:1::50".into()),
            allowed_networks: vec!["10.0.0.0/8".into(), "2001:db8:100::/48".into()],
            client_subnets: vec!["192.168.50.0/24".into(), "2001:db8:200::/56".into()],
            ..Default::default()
        };
        user.routes.push(UserRoute {
            cidr: "2001:db8:300::/48".into(),
            gateway: Some("fd71:e1:1234:1::1".into()),
            metric: Some(10),
        });
        let db = UsersDb {
            users: vec![user.clone()],
            groups: HashMap::new(),
        };
        db.validate_network_fields().unwrap();

        user.routes[0].gateway = Some("10.9.0.1".into());
        let error = UsersDb {
            users: vec![user],
            groups: HashMap::new(),
        }
        .validate_network_fields()
        .unwrap_err()
        .to_string();
        assert!(error.contains("different address families"), "{error}");
    }

    #[test]
    fn invalid_static_ipv6_is_rejected_before_it_can_be_saved() {
        let db = UsersDb {
            users: vec![UserEntry {
                username: "alice".into(),
                static_ipv6: Some("fe80::1".into()),
                ..Default::default()
            }],
            groups: HashMap::new(),
        };
        let error = db.validate_network_fields().unwrap_err().to_string();
        assert!(error.contains("link-local"), "{error}");
    }

    #[test]
    fn duplicate_static_addresses_are_rejected_centrally() {
        let users = vec![
            UserEntry {
                username: "alice".into(),
                static_ip: Some("10.9.0.50".into()),
                static_ipv6: Some("fd71:e1:1234:1::50".into()),
                ..Default::default()
            },
            UserEntry {
                username: "bob".into(),
                static_ip: Some("10.9.0.50".into()),
                static_ipv6: Some("fd71:e1:1234:1:0:0:0:50".into()),
                ..Default::default()
            },
        ];
        let ipv4_error = UsersDb {
            users: users.clone(),
            groups: HashMap::new(),
        }
        .validate_network_fields()
        .unwrap_err()
        .to_string();
        assert!(ipv4_error.contains("same static_ip"), "{ipv4_error}");

        let mut ipv6_users = users;
        ipv6_users[1].static_ip = Some("10.9.0.51".into());
        let ipv6_error = UsersDb {
            users: ipv6_users,
            groups: HashMap::new(),
        }
        .validate_network_fields()
        .unwrap_err()
        .to_string();
        assert!(ipv6_error.contains("same static_ipv6"), "{ipv6_error}");
    }

    /// A MISSPELLED key must refuse the load too — the more dangerous half of the same bug.
    ///
    /// `max_sessions = ten` is an unreadable value under a correct key and was already caught.
    /// `max_session = 1` is a correct value under a misspelled key: nothing reads it, the real
    /// `max_sessions` stays 0, and 0 on this file means NO LIMIT. The restriction is simply
    /// absent while the file still appears to state it. It also compounds — the codec that
    /// rewrites this file cannot see the typo, so the next panel edit drops the line and the
    /// evidence with it. (Audit 2026-08-02, follow-up.)
    #[test]
    #[cfg(unix)]
    fn a_misspelled_key_refuses_the_load_and_the_write() {
        let dir = std::env::temp_dir().join("qeli-users-unread-test");
        std::fs::create_dir_all(&dir).unwrap();

        let typo = dir.join("typo.conf");
        std::fs::write(&typo, "[user:alice]\npassword_hash = x\nmax_session = 1\n").unwrap();
        let err = UsersDb::load(&typo)
            .expect_err("a misspelled key must refuse the load")
            .to_string();
        assert!(
            err.contains("max_session"),
            "the error must name the key: {err}"
        );

        // The WRITE path must refuse it too, or the panel launders the typo away.
        let write_err = UsersDb::update_locked(&typo, |db| db.users.len())
            .expect_err("the write path must refuse it as well")
            .to_string();
        assert!(write_err.contains("max_session"), "{write_err}");
        // ...and the file is untouched, so the operator can still see what they wrote.
        assert!(std::fs::read_to_string(&typo)
            .unwrap()
            .contains("max_session = 1"));

        // An unreadable VALUE must be refused on the write path too.
        //
        // Its own check existed but ran BEFORE `from_ini`, and `bad_values` is populated BY the
        // readers inside `from_ini` — so it asked a freshly-parsed document, got nothing, and
        // passed. Vacuous rather than absent, which is the harder kind to notice: the code
        // reads as though the case is covered. This assertion is what makes it real.
        let bad_value = dir.join("bad-value.conf");
        std::fs::write(
            &bad_value,
            "[user:alice]\npassword_hash = x\nmax_sessions = ten\n",
        )
        .unwrap();
        let value_err = UsersDb::update_locked(&bad_value, |_| ())
            .expect_err("an unreadable value must refuse the write")
            .to_string();
        assert!(value_err.contains("max_sessions"), "{value_err}");
        assert!(std::fs::read_to_string(&bad_value)
            .unwrap()
            .contains("= ten"));

        // The correctly-spelled file still loads AND still writes — otherwise this would pass
        // against a check that simply refuses everything.
        let good = dir.join("spelled.conf");
        std::fs::write(&good, "[user:alice]\npassword_hash = x\nmax_sessions = 1\n").unwrap();
        assert_eq!(UsersDb::load(&good).expect("must load").users.len(), 1);
        UsersDb::update_locked(&good, |_| ()).expect("must write");
    }

    /// An unreadable LIMIT must refuse the load, not fall back to "no limit".
    ///
    /// The disabled value for these fields is zero, so `max_sessions = ten` and
    /// `data_limit_gb = 50G` both land on 0 — which does not mean "default", it means
    /// UNLIMITED. A typo therefore removes the very restriction it was written to impose, on
    /// the one file where that matters most. (Audit 2026-08-02, §5.)
    #[test]
    fn an_unreadable_limit_refuses_the_load() {
        let dir = std::env::temp_dir().join("qeli-users-load-test");
        std::fs::create_dir_all(&dir).unwrap();

        let good = dir.join("good.conf");
        std::fs::write(
            &good,
            "[user:alice]\npassword_hash = x\nmax_sessions = 3\ndata_limit_gb = 50\n",
        )
        .unwrap();
        let db = UsersDb::load(&good).expect("a sound file must load");
        assert_eq!(db.users.len(), 1);
        assert_eq!(db.users[0].max_sessions, 3);

        for (label, body) in [
            (
                "max_sessions",
                "[user:alice]\npassword_hash = x\nmax_sessions = ten\n",
            ),
            (
                "data_limit_gb",
                "[user:alice]\npassword_hash = x\ndata_limit_gb = 50G\n",
            ),
        ] {
            let bad = dir.join(format!("bad-{label}.conf"));
            std::fs::write(&bad, body).unwrap();
            let err = UsersDb::load(&bad).expect_err(&format!(
                "{label}: an unreadable limit must refuse the load"
            ));
            assert!(
                err.to_string().contains(label),
                "{label}: the error must name the key: {err}"
            );
            let _ = std::fs::remove_file(&bad);
        }

        // A MISSING file is a different thing entirely — the caller turns that into an empty
        // database on first run, so it must surface as an io error rather than as a parse one.
        let missing = dir.join("does-not-exist.conf");
        let _ = std::fs::remove_file(&missing);
        let err = UsersDb::load(&missing).expect_err("a missing file must error");
        assert!(
            err.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "a missing file must be NotFound, not a parse failure: {err}"
        );

        let _ = std::fs::remove_file(&good);
    }

    #[test]
    fn malformed_allowed_networks_refuses_users_and_groups() {
        let dir = std::env::temp_dir().join(format!("qeli-users-acl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        for (name, body) in [
            (
                "user",
                "[user:alice]\npassword_hash = x\nallowed_networks = 10.0.0.0/99\n",
            ),
            ("group", "[group:staff]\nallowed_networks = not-a-network\n"),
        ] {
            let path = dir.join(format!("{name}.conf"));
            std::fs::write(&path, body).unwrap();
            let err = UsersDb::load(&path)
                .expect_err("a malformed destination ACL must refuse the database")
                .to_string();
            assert!(err.contains("allowed_networks"), "{err}");
        }

        let _ = std::fs::remove_dir_all(&dir);
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

    #[cfg(unix)]
    fn tmp_users(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!("qeli-users-test-{tag}.conf"));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{}.lock", p.display()));
        p.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    fn named(n: &str) -> UserEntry {
        UserEntry {
            username: n.to_string(),
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    #[cfg(unix)]
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
