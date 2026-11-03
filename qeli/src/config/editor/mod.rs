//! Pure, bounded configuration document service shared by every native adapter.
//! JSON is an in-process service DTO only. Profile documents are INI or qeli://.
pub mod schema;
use super::{
    client::ClientConfig,
    format::{IniDoc, Section},
    share::ClientLink,
};
use schema::FIELDS;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use zeroize::Zeroize;
pub const MAX_REQUEST: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;
const MAX_DOCUMENT: usize = 256 * 1024;

fn field(key: &str) -> Option<&'static schema::Field> {
    FIELDS.iter().find(|f| f.key == key)
}
fn default_value(f: &schema::Field) -> Value {
    match f.kind {
        "bool" => json!(f.default == "true"),
        "int" => json!(f.default.parse::<i64>().unwrap()),
        "list" | "lines" => json!([]),
        _ => json!(f.default),
    }
}
fn key_parts(key: &str) -> (&str, &str) {
    if key == "tun.tx_queue_len" {
        ("qeli", key)
    } else {
        key.split_once('.').unwrap_or(("qeli", key))
    }
}
fn safe(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.chars().any(|c| c.is_control() && c != '\t'),
        "configuration value contains an unsupported control character"
    );
    Ok(())
}
fn texts(value: &Value, lines: bool) -> anyhow::Result<Vec<String>> {
    if let Some(a) = value.as_array() {
        let a = a
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| anyhow::anyhow!("list element must be text"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        for v in &a {
            safe(v)?;
            anyhow::ensure!(!v.contains(',') || lines, "list element contains a comma");
        }
        return Ok(if lines {
            a.iter().map(|s| s.to_string()).collect()
        } else {
            vec![a.join(", ")]
        });
    }
    let text = match value {
        Value::String(v) => v.clone(),
        Value::Bool(_) | Value::Number(_) => value.to_string(),
        Value::Null => return Ok(vec![]),
        _ => anyhow::bail!("invalid field type"),
    };
    safe(&text)?;
    Ok(vec![text])
}
fn set(doc: &mut IniDoc, key: &str, value: &Value) -> anyhow::Result<()> {
    let (section, name) = key_parts(key);
    anyhow::ensure!(
        !section.is_empty()
            && section.trim() == section
            && !section.chars().any(char::is_control)
            && !section.contains(['[', ']', '=', ':']),
        "invalid section name"
    );
    anyhow::ensure!(
        !name.is_empty()
            && name.trim() == name
            && !name.chars().any(char::is_control)
            && !name.starts_with(['#', ';'])
            && !name.contains(['=', '[', ']']),
        "invalid field name"
    );
    let entries = texts(value, field(key).is_some_and(|f| f.kind == "lines"))
        .map_err(|_| anyhow::anyhow!("{key}: invalid value, list item or control character"))?;
    for sec in &mut doc.sections {
        if sec.kind == section && sec.instance.is_none() {
            sec.entries.retain(|(k, _)| k != name);
        }
    }
    if !doc
        .sections
        .iter()
        .any(|s| s.kind == section && s.instance.is_none())
    {
        doc.push(Section::new(section, None));
    }
    let sec = doc
        .sections
        .iter_mut()
        .find(|s| s.kind == section && s.instance.is_none())
        .unwrap();
    for text in entries {
        sec.entries.push((name.to_string(), text));
    }
    Ok(())
}
fn bounds(key: &str) -> (i64, i64) {
    match key {
        "mtu" => (0, super::server::MTU_MAX as i64),
        "jc" => (0, 128),
        "jmin" | "jmax" | "padding_min" | "padding_max" => (0, super::MAX_PADDING_BYTES as i64),
        "metric" => (0, i32::MAX as i64),
        "timeout" => (1, 300),
        "reconnect_retries" => (-1, i32::MAX as i64),
        "reconnect_base_delay" | "reconnect_max_delay" => (1, 86400),
        "lport" => (0, 65535),
        "tun.tx_queue_len" => (1, super::client::CLIENT_TUN_TX_QUEUE_LEN_MAX as i64),
        "recv_buffer_size" | "send_buffer_size" => (0, 64 * 1024 * 1024),
        "heartbeat_size" | "shaping_min_size" | "shaping_max_size" => (0, 65535),
        "heartbeat_interval"
        | "shaping_gap_mean"
        | "shaping_gap_min"
        | "shaping_gap_max"
        | "shaping_budget"
        | "shaping_stealth_mbps" => (1, i32::MAX as i64),
        _ => (0, i32::MAX as i64),
    }
}
fn convert(f: &schema::Field, raw: &[String]) -> anyhow::Result<Value> {
    let text = raw.first().map(String::as_str).unwrap_or("");
    match f.kind {
        "bool" => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Ok(json!(true)),
            "false" | "no" | "off" | "0" => Ok(json!(false)),
            _ => anyhow::bail!("invalid boolean"),
        },
        "int" => {
            let t = text.trim();
            let n = t.parse::<i64>()?;
            let (min, max) = bounds(f.key);
            anyhow::ensure!(
                (min..=max).contains(&n) && !(min >= 0 && t.starts_with('-')),
                "number outside allowed range"
            );
            Ok(json!(n))
        }
        "list" => {
            for text in raw {
                anyhow::ensure!(
                    text.is_empty() || text.split(',').all(|v| !v.trim().is_empty()),
                    "empty list member"
                );
            }
            Ok(json!(raw
                .iter()
                .flat_map(|s| s.split(','))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()))
        }
        "lines" => Ok(json!(raw)),
        _ => Ok(json!(text)),
    }
}
struct Document {
    doc: IniDoc,
    values: Map<String, Value>,
    diagnostics: Vec<Value>,
    raw: BTreeMap<String, Vec<String>>,
}
impl Drop for Document {
    fn drop(&mut self) {
        for sec in &mut self.doc.sections {
            for (_, v) in &mut sec.entries {
                v.zeroize();
            }
        }
        wipe(&mut Value::Object(std::mem::take(&mut self.values)));
        for v in self.raw.values_mut() {
            for s in v {
                s.zeroize();
            }
        }
    }
}
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}
fn inspect(mut doc: IniDoc) -> anyhow::Result<Document> {
    for sec in &mut doc.sections {
        sec.kind = sec.kind.to_ascii_lowercase();
        for (key, _) in &mut sec.entries {
            *key = key.to_ascii_lowercase();
        }
    }
    let mut d = Document {
        doc,
        values: Map::new(),
        diagnostics: vec![],
        raw: BTreeMap::new(),
    };
    for f in FIELDS {
        d.values.insert(f.key.into(), default_value(f));
    }
    let mut sections = std::collections::HashSet::new();
    for sec in &d.doc.sections {
        if sec.instance.is_some()
            || !matches!(sec.kind.as_str(), "qeli" | "logging")
            || !sections.insert(&sec.kind)
        {
            d.diagnostics.push(json!({"key":sec.header(),"code":"section","message":"invalid or repeated client section"}));
        }
        for (k, v) in &sec.entries {
            safe(v)?;
            let key = if sec.kind == "qeli" && (!k.contains('.') || k == "tun.tx_queue_len") {
                k.clone()
            } else {
                // Other dotted schema names denote a section plus its local key. A literal
                // `logging.level` under [qeli] must not alias [logging] level.
                format!("{}.{}", sec.kind, k)
            };
            d.raw.entry(key).or_default().push(v.clone());
        }
    }
    anyhow::ensure!(
        sections.contains(&"qeli".to_string()),
        "missing [qeli] section"
    );
    for (key, raw) in &d.raw {
        if let Some(f) = field(key) {
            if raw.len() > 1 && !matches!(f.kind, "list" | "lines") {
                d.diagnostics
                    .push(json!({"key":key,"code":"duplicate","message":"duplicate scalar field"}));
            }
            match convert(f, raw) {
                Ok(v) => {
                    d.values.insert(key.clone(), v);
                }
                Err(_) => {
                    d.diagnostics
                        .push(json!({"key":key,"code":f.kind,"message":"invalid field value"}));
                }
            }
        } else {
            d.diagnostics
                .push(json!({"key":key,"code":"unknown","message":"unknown configuration field"}));
        }
    }
    // Migrate the historical GUI resolver spelling in one place. Typo modes stay errors.
    if let Some(dns) = d.values["dns"]
        .as_str()
        .filter(|v| !matches!(*v, "tunnel" | "off" | "system"))
    {
        let ips: Vec<_> = dns.split(',').map(str::trim).collect();
        if d.raw.get("dns").is_some_and(|raw| raw.len() == 1)
            && !d
                .diagnostics
                .iter()
                .any(|error| error["key"] == "dns_servers")
            && !ips.is_empty()
            && ips.iter().all(|v| v.parse::<std::net::IpAddr>().is_ok())
        {
            if !d.raw.contains_key("dns_servers") {
                d.values.insert("dns_servers".into(), json!(ips));
            }
            d.values.insert("dns".into(), json!("tunnel"));
            set(&mut d.doc, "dns", &d.values["dns"])?;
            set(&mut d.doc, "dns_servers", &d.values["dns_servers"])?;
            // Rebuild raw/diagnostics from the canonical document. The mode is now
            // "tunnel", so this normalization runs at most once. Invalid DNS fields
            // are never rewritten; their diagnostics must survive an editor round-trip.
            return inspect(d.doc.clone());
        }
    }
    match d.values["mode"].as_str().unwrap_or("") {
        "udp-quic" => {
            d.values.insert("mode".into(), json!("fake-tls"));
            d.values.insert("proto".into(), json!("udp"));
            d.values.insert("quic".into(), json!(true));
        }
        "udp-obfs" => {
            d.values.insert("mode".into(), json!("obfs"));
            d.values.insert("proto".into(), json!("udp"));
        }
        _ => {}
    }
    if d.values["padding_min"].as_i64().unwrap() > d.values["padding_max"].as_i64().unwrap() {
        d.diagnostics
            .push(json!({"key":"padding_min","code":"int","message":"inverted padding range"}));
        d.values
            .insert("padding_min".into(), d.values["padding_max"].clone());
    }
    let server = d.values["server"].as_str().unwrap_or("");
    let (host, port) = match super::client::split_host_port(server) {
        Ok(v) => v,
        Err(_) => {
            anyhow::ensure!(
                !server.starts_with('[') && server.matches(':').count() <= 1,
                "server has an invalid IPv6 endpoint; use [address]:port"
            );
            d.diagnostics.push(json!({"key":"server (port)","code":"int","message":"invalid server endpoint or port"}));
            (
                server
                    .rsplit_once(':')
                    .map(|(h, _)| h)
                    .unwrap_or(server)
                    .to_string(),
                443,
            )
        }
    };
    d.values.insert("$host".into(), json!(host));
    d.values.insert("$port".into(), json!(port));
    Ok(d)
}
// Normalize only the file/link preamble. Trimming the complete document would
// discard a trailing control character before the INI parser can reject it.
fn source_text(source: &str) -> &str {
    source.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n'])
}

fn parse(source: &str) -> anyhow::Result<Document> {
    anyhow::ensure!(
        source.len() <= MAX_DOCUMENT,
        "configuration exceeds 256 KiB"
    );
    let text = source_text(source);
    anyhow::ensure!(
        !text.starts_with('{'),
        "configuration files must be INI; JSON profiles are no longer supported"
    );
    if text.starts_with("qeli://") {
        let mut link = ClientLink::from_uri(text.trim_end_matches([' ', '\t', '\r', '\n']))?;
        let cfg = ClientConfig::from_link(&link);
        let mut doc = IniDoc::parse(&cfg.to_ini_string())?;
        set(&mut doc, "name", &json!(link.label))?;
        link.pass.zeroize();
        link.obfs_key.zeroize();
        inspect(doc)
    } else {
        inspect(IniDoc::parse(text)?)
    }
}
fn materialize(d: &Document) -> anyhow::Result<IniDoc> {
    let mut doc = d.doc.clone();
    for f in FIELDS {
        // Explicit runtime defaults eliminate GUI/native drift while absence of tuning
        // and foreign fields (notably automatic socket buffers) remains significant.
        if (d.raw.contains_key(f.key) || f.cs != "-" && f.kotlin != "-" && f.swift != "-")
            && !d
                .diagnostics
                .iter()
                .any(|v| v["key"] == f.key || f.key == "server" && v["key"] == "server (port)")
        {
            set(&mut doc, f.key, &d.values[f.key])?;
        }
    }
    Ok(doc)
}
fn validate(d: &Document) -> anyhow::Result<()> {
    if !d.diagnostics.is_empty() {
        anyhow::bail!(
            "{}",
            d.diagnostics
                .iter()
                .map(|e| format!(
                    "{}{}: {}",
                    if e["key"].as_str().unwrap_or("").contains('.') {
                        ""
                    } else {
                        "qeli."
                    },
                    e["key"].as_str().unwrap_or("config"),
                    e["message"].as_str().unwrap_or("invalid value")
                ))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    if d.values["apps_mode"] != "all" {
        anyhow::ensure!(
            !d.values["apps"].as_array().unwrap().is_empty(),
            "apps_mode include/exclude requires a non-empty apps list"
        );
        anyhow::ensure!(
            !["forward", "gateway_nat", "exit_node"]
                .iter()
                .any(|k| d.values[*k] == true),
            "per-app policy cannot be combined with LAN forwarding or gateway NAT"
        );
    }
    anyhow::ensure!(
        matches!(
            d.values["apps_mode"].as_str(),
            Some("all" | "include" | "exclude")
        ),
        "invalid apps_mode"
    );
    for key in ["include", "exclude"] {
        for v in d.values[key].as_array().unwrap() {
            anyhow::ensure!(
                v.as_str().unwrap().parse::<ipnet::IpNet>().is_ok(),
                "invalid {key} CIDR"
            );
        }
    }
    let doc = materialize(d)?;
    let cfg = ClientConfig::from_ini(&doc)?;
    anyhow::ensure!(
        doc.bad_values().is_empty(),
        "{}",
        doc.bad_values().join("; ")
    );
    cfg.validate()?;
    Ok(())
}
fn response(d: &Document) -> Value {
    json!({"values":d.values,"source":d.doc.to_string(),"diagnostics":d.diagnostics,"raw":d.raw})
}
fn execute(req: &Value) -> anyhow::Result<Value> {
    anyhow::ensure!(req["version"] == 1, "unsupported editor API version");
    let op = req["op"].as_str().unwrap_or("");
    if op == "schema" {
        let fields = FIELDS
            .iter()
            .map(|f| {
                let mut value = serde_json::to_value(f).unwrap();
                value["sensitive"] = json!(schema::sensitive(f.key));
                if f.kind == "int" {
                    let (min, max) = bounds(f.key);
                    value["min"] = json!(min);
                    value["max"] = json!(max);
                }
                value
            })
            .collect::<Vec<_>>();
        return Ok(json!({"fields":fields}));
    }
    if op == "policy" {
        return super::policy::execute(req);
    }
    anyhow::ensure!(
        req["source"].is_null() || req["source"].is_string(),
        "source must be text"
    );
    for key in ["values", "patch"] {
        anyhow::ensure!(
            req[key].is_null() || req[key].is_object(),
            "{key} must be an object"
        );
    }
    anyhow::ensure!(
        req["unresolved"].is_null()
            || req["unresolved"]
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_string)),
        "unresolved must be a list of field names"
    );
    let source = req["source"]
        .as_str()
        .unwrap_or("[qeli]\nserver = localhost:443\n");
    let mut d = parse(source)?;
    if let Some(values) = req["values"].as_object() {
        let routing_mode = values
            .get("$routing_mode")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase);
        if let Some(mode) = routing_mode.as_deref() {
            anyhow::ensure!(
                matches!(mode, "full-tunnel" | "split-tunnel" | "all"),
                "unknown routing mode"
            );
        }
        let repaired: Vec<String> = if let Some(unresolved) = req["unresolved"].as_array() {
            d.diagnostics
                .iter()
                .filter(|e| {
                    matches!(e["code"].as_str(), Some("bool" | "int"))
                        && !unresolved.contains(&e["key"])
                        // An omitted unresolved marker only acknowledges a repair
                        // when the request actually supplies that field's value.
                        && e["key"].as_str().is_some_and(|key| {
                            values.contains_key(if key == "server (port)" { "$port" } else { key })
                        })
                })
                .filter_map(|e| e["key"].as_str().map(str::to_string))
                .collect()
        } else {
            vec![]
        };
        let host = values
            .get("$host")
            .and_then(Value::as_str)
            .unwrap_or(d.values["$host"].as_str().unwrap());
        let port = match values.get("$port") {
            Some(v) => v
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("server port must be 1..65535"))?,
            None => d.values["$port"].as_u64().unwrap(),
        };
        anyhow::ensure!((1..=65535).contains(&port), "server port must be 1..65535");
        if repaired.iter().any(|k| k == "server (port)")
            || req["source"].is_null()
            || values
                .get("$host")
                .is_some_and(|v| Some(v) != d.values.get("$host"))
            || values
                .get("$port")
                .is_some_and(|v| Some(v) != d.values.get("$port"))
        {
            let endpoint = crate::util::join_host_port(host, port as u16);
            set(&mut d.doc, "server", &json!(endpoint))?;
        }
        for (key, value) in values {
            // Unmodelled fields arrive as raw text from carriedKeys. Compare their
            // typed value before deciding to rewrite, otherwise "true" != true would
            // silently collapse duplicate foreign keys during an unrelated form edit.
            let comparable = match (field(key), value.as_str()) {
                (Some(f), Some(raw)) if matches!(f.kind, "bool" | "int") => {
                    convert(f, &[raw.to_string()]).unwrap_or_else(|_| value.clone())
                }
                _ => value.clone(),
            };
            let unchanged_raw = value.as_str().is_some_and(|v| {
                d.raw
                    .get(key)
                    .and_then(|items| items.first())
                    .is_some_and(|raw| raw == v)
            });
            if !key.starts_with('$')
                && (req["source"].is_null()
                    || repaired.contains(key)
                    || !unchanged_raw && d.values.get(key) != Some(&comparable))
            {
                set(&mut d.doc, key, value)?;
            }
        }
        // Legacy form models carry two routing controls. Preserve their documented OR
        // semantics centrally; an imported gateway=false already projects split-tunnel.
        if matches!(routing_mode.as_deref(), Some("full-tunnel" | "all"))
            && values.get("gateway") == Some(&Value::Bool(false))
        {
            set(&mut d.doc, "gateway", &json!(true))?;
        }
        d = inspect(d.doc.clone())?;
    }
    if let Some(patch) = req["patch"].as_object() {
        for (key, value) in patch {
            anyhow::ensure!(!key.starts_with('$'), "patch requires INI field names");
            set(&mut d.doc, key, value)?;
        }
        d = inspect(d.doc.clone())?;
    }
    anyhow::ensure!(
        d.doc.to_string().len() <= MAX_DOCUMENT,
        "configuration exceeds 256 KiB after edit"
    );
    match op {
        "import" => {
            if source_text(source).starts_with("qeli://") {
                validate(&d)?;
            }
            Ok(response(&d))
        }
        "export" => Ok(json!({"text":d.doc.to_string()})),
        "runtime" => {
            validate(&d)?;
            let mut doc = materialize(&d)?;
            // iOS carries desktop policy in the portable document. NetworkExtension
            // has no desktop firewall capability; its On Demand protection is OS-owned.
            if req["platform"] == "ios" {
                set(&mut doc, "kill_switch", &Value::Null)?;
            }
            Ok(json!({"text":doc.to_string()}))
        }
        "validate" => {
            validate(&d)?;
            Ok(json!({"valid":true}))
        }
        "probe" => {
            validate(&d)?;
            let mut doc = IniDoc::new();
            doc.push(Section::new("qeli", None));
            for key in ["server", "proto", "mode", "sni", "obfs_key", "quic"] {
                set(&mut doc, key, &d.values[key])?;
            }
            Ok(json!({"text":doc.to_string()}))
        }
        "uri" => {
            validate(&d)?;
            let cfg = ClientConfig::from_ini(&materialize(&d)?)?;
            // A share link cannot carry password_file/password_command. Without an
            // inline password it would import successfully but fail at connect time.
            anyhow::ensure!(
                cfg.auth.password.as_deref().is_some_and(|pass| !pass.is_empty()),
                "cannot share profile as qeli:// without an inline pass; set pass in the INI before sharing"
            );
            let label = d.values["name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            Ok(json!({"text":cfg.to_link(label).to_uri()}))
        }
        _ => anyhow::bail!("unknown editor operation"),
    }
}
fn redact_error(mut message: String, req: &Value) -> String {
    let mut secrets = Vec::new();
    for overlay in ["values", "patch"] {
        if let Some(values) = req[overlay].as_object() {
            for (key, value) in values {
                let key = key.to_ascii_lowercase();
                let (section, name) = key_parts(&key);
                if section == "qeli" && schema::sensitive(name) {
                    if let Ok(mut values) = texts(value, false) {
                        secrets.append(&mut values);
                    }
                }
            }
        }
    }
    if let Some(source) = req["source"].as_str() {
        let source = source_text(source);
        if source.starts_with("qeli://") {
            if let Ok(mut link) =
                ClientLink::from_uri(source.trim_end_matches([' ', '\t', '\r', '\n']))
            {
                secrets.push(std::mem::take(&mut link.pass));
                if let Some(value) = link.obfs_key.take() {
                    secrets.push(value);
                }
                if let Some(value) = link.reality_sid.take() {
                    secrets.push(value);
                }
            }
        } else if let Ok(mut doc) = IniDoc::parse(source) {
            for sec in &mut doc.sections {
                for (name, value) in &mut sec.entries {
                    if sec.kind.eq_ignore_ascii_case("qeli")
                        && schema::sensitive(&name.to_ascii_lowercase())
                    {
                        secrets.push(std::mem::take(value));
                    } else {
                        value.zeroize();
                    }
                }
            }
        }
    }
    // Replace longer values first so one secret cannot expose the suffix of another.
    secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
    for secret in secrets.iter().filter(|value| !value.is_empty()) {
        message = message.replace(&format!("'{secret}'"), "'[redacted]'");
        if secret.len() > 4 {
            message = message.replace(secret, "[redacted]");
        }
    }
    secrets.zeroize();
    message
}

/// No I/O, DNS, command execution, session or global mutable document registry.
pub fn request(bytes: &[u8]) -> Vec<u8> {
    let result = (|| -> anyhow::Result<Value> {
        anyhow::ensure!(bytes.len() <= MAX_REQUEST, "editor request too large");
        let mut req: Value = serde_json::from_slice(bytes)?;
        let result = execute(&req);
        // Errors returned to the UI must not reveal credential values from any parser.
        let result = result.map_err(|e| anyhow::anyhow!(redact_error(e.to_string(), &req)));
        wipe(&mut req);
        result
    })();
    let value = match result {
        Ok(v) => json!({"ok":true,"result":v}),
        Err(e) => json!({"ok":false,"error":e.to_string()}),
    };
    let mut value = value;
    let mut output = serde_json::to_vec(&value).unwrap_or_default();
    wipe(&mut value);
    if output.len() > MAX_RESPONSE {
        output.zeroize();
        br#"{"ok":false,"error":"editor response too large"}"#.to_vec()
    } else {
        output
    }
}

/// The standalone Rust client and the editor materialize the same portable defaults.
pub(crate) fn apply_client_defaults(cfg: &mut ClientConfig) {
    cfg.routing.add_default_gateway = field("gateway").unwrap().default == "true";
    cfg.routing.pull_routes = field("pull_routes").unwrap().default == "true";
    cfg.obfuscation.padding.min_bytes = field("padding_min").unwrap().default.parse().unwrap();
    cfg.obfuscation.padding.max_bytes = field("padding_max").unwrap().default.parse().unwrap();
    cfg.obfuscation.heartbeat.jitter_ms =
        field("heartbeat_jitter").unwrap().default.parse().unwrap();
}
/// The panel's automatic TUN assignment must use the same case/BOM/section
/// rules as runtime without serializing away comments from the original file.
pub fn explicit_device(source: &str) -> anyhow::Result<Option<String>> {
    let d = parse(source)?;
    validate(&d)?;
    Ok(d.raw
        .get("dev")
        .and_then(|values| values.first())
        .filter(|value| !value.is_empty())
        .cloned())
}

pub fn parse_runtime(source: &str) -> anyhow::Result<ClientConfig> {
    let d = parse(source)?;
    validate(&d)?;
    ClientConfig::from_ini(&materialize(&d)?)
}

#[cfg(test)]
mod tun_queue_tests;
