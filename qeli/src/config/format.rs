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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Section {
    /// The part before `:` in the header, e.g. `profile` in `[profile:tcp]`,
    /// or the whole name for a singleton like `[auth]`.
    pub kind: String,
    /// The part after `:`, e.g. `tcp` in `[profile:tcp]`. `None` for singletons.
    pub instance: Option<String>,
    /// `(key, value)` pairs, in source order. Duplicate keys are preserved
    /// (use [`Section::list`] / [`Section::all`] to read repeated keys).
    pub entries: Vec<(String, String)>,
}

impl Section {
    pub fn new(kind: impl Into<String>, instance: Option<String>) -> Self {
        Self {
            kind: kind.into(),
            instance,
            entries: Vec::new(),
        }
    }

    /// First value for `key`, or `None` if absent.
    pub fn get(&self, key: &str) -> Option<&str> {
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
    /// key is absent, empty, or fails to parse.
    pub fn parse_or<T: std::str::FromStr>(&self, key: &str, default: T) -> T {
        match self.get(key) {
            Some(v) if !v.is_empty() => v.parse().unwrap_or(default),
            _ => default,
        }
    }

    /// Booleans accept `true/false`, `yes/no`, `on/off`, `1/0` (case
    /// insensitive). Anything else (or absent) yields `default`.
    pub fn bool_or(&self, key: &str, default: bool) -> bool {
        match self.get(key).map(|v| v.trim().to_ascii_lowercase()) {
            Some(v) => match v.as_str() {
                "true" | "yes" | "on" | "1" => true,
                "false" | "no" | "off" | "0" => false,
                _ => default,
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
                Some(inst) => writeln!(f, "[{}:{}]", sec.kind, inst)?,
                None => writeln!(f, "[{}]", sec.kind)?,
            }
            for (k, v) in &sec.entries {
                writeln!(f, "{} = {}", k, quote_if_needed(v))?;
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

/// Strip a single pair of surrounding double-quotes, if present. Quotes let a
/// value keep significant leading/trailing whitespace or a literal `;`/`#`.
fn unquote(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn quote_if_needed(s: &str) -> String {
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
}
