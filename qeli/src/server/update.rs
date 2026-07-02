//! Opt-in "check for updates": query GitHub Releases for a newer qeli version.
//!
//! PRIVACY — qeli is a privacy / censorship-resistance VPN. This check is OFF by
//! default and only runs when the operator explicitly asks for it (`qeli version
//! --check`). It makes ONE unauthenticated GET of PUBLIC release metadata with a
//! GENERIC User-Agent — it sends no version, no id, nothing that individualizes the
//! host; the comparison happens locally. It is notification-only: it reports the
//! latest version and the release page URL and NEVER downloads or installs anything.
//!
//! It reads the releases LIST (not `/releases/latest`, which silently skips
//! pre-releases — and every qeli release so far is a pre-release), mirroring
//! `install-reality-server.sh`. TLS reuses the notify rustls(ring) + webpki-roots
//! stack, so the GitHub certificate is properly verified. Any failure is returned as
//! an `Err(reason)` so the caller can stay quiet / fail soft.

use super::notify::{parse_url, tls_connector};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RELEASES_URL: &str = "https://api.github.com/repos/litvinovtd/qeli/releases";
const RELEASES_PAGE: &str = "https://github.com/litvinovtd/qeli/releases";
/// GitHub 403s a request with no User-Agent, but a qeli-branded UA hitting
/// api.github.com is itself a "this host runs qeli" fingerprint — so send a generic,
/// non-identifying value.
const GENERIC_UA: &str = "Mozilla/5.0";
const GET_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 512 * 1024;

/// The version this binary was built as.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[derive(Debug, Clone)]
pub struct LatestRelease {
    /// Normalized version of the newest non-draft release, e.g. "0.7.6".
    pub tag: String,
    /// Human release page (the release's `html_url`) to open in a browser.
    pub url: String,
    /// True if `tag` is strictly newer than [`current_version`].
    pub is_newer: bool,
    /// `browser_download_url` of the `.deb` asset (for the operator's update command), if any.
    pub deb_url: Option<String>,
    /// `browser_download_url` of the `SHA256SUMS` asset (to verify the download), if any.
    pub sha_url: Option<String>,
}

/// Best-effort detection of how this server was installed, so the update instructions
/// we show match reality: `docker` (update by pulling the image), `deb` (dpkg), or
/// `other` (raw binary). Never panics.
pub fn install_kind() -> &'static str {
    if std::path::Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|s| s.contains("docker") || s.contains("containerd"))
            .unwrap_or(false)
    {
        "docker"
    } else if std::path::Path::new("/var/lib/dpkg/info/qeli.list").exists() {
        "deb"
    } else {
        "other"
    }
}

/// From a release object, pick the `.deb` asset URL and the `SHA256SUMS` asset URL
/// (both by `browser_download_url`) — used to build a copy-paste update command.
fn pick_assets(rel: &serde_json::Value) -> (Option<String>, Option<String>) {
    let assets = match rel.get("assets").and_then(serde_json::Value::as_array) {
        Some(a) => a,
        None => return (None, None),
    };
    let mut deb = None;
    let mut sha = None;
    for a in assets {
        let name = a
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let url = a
            .get("browser_download_url")
            .and_then(serde_json::Value::as_str);
        if name.ends_with(".deb") && deb.is_none() {
            deb = url.map(str::to_string);
        } else if name == "SHA256SUMS" {
            sha = url.map(str::to_string);
        }
    }
    (deb, sha)
}

/// Fetch the newest non-draft release (pre-releases INCLUDED) and compare it to the
/// current build. Returns `Err(reason)` on any network / parse failure.
pub async fn check_latest() -> Result<LatestRelease, String> {
    let body = tokio::time::timeout(GET_TIMEOUT, http_get_body(RELEASES_URL))
        .await
        .map_err(|_| "timed out".to_string())??;
    let json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("parse: {e}"))?;
    let arr = json.as_array().ok_or("unexpected response shape")?;
    for rel in arr {
        // Skip drafts; accept pre-releases (see module docs).
        if rel.get("draft").and_then(serde_json::Value::as_bool) == Some(true) {
            continue;
        }
        let tag = match rel.get("tag_name").and_then(serde_json::Value::as_str) {
            Some(t) if !t.is_empty() => t,
            _ => continue,
        };
        let url = rel
            .get("html_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(RELEASES_PAGE)
            .to_string();
        let norm = normalize(tag);
        let is_newer = is_newer(&norm, current_version());
        let (deb_url, sha_url) = pick_assets(rel);
        return Ok(LatestRelease {
            tag: norm,
            url,
            is_newer,
            deb_url,
            sha_url,
        });
    }
    Err("no releases found".into())
}

/// One-shot HTTPS GET returning the response body (headers stripped, chunked decoded).
async fn http_get_body(url: &str) -> Result<Vec<u8>, String> {
    let (https, host, port, path) = parse_url(url)?;
    if !https {
        return Err("update check requires https".into());
    }
    let stream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {GENERIC_UA}\r\n\
         Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes();
    let connector = tls_connector()?;
    let name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| format!("invalid TLS host '{host}'"))?;
    let mut tls = connector
        .connect(name, stream)
        .await
        .map_err(|e| format!("tls handshake: {e}"))?;
    tls.write_all(&req)
        .await
        .map_err(|e| format!("write: {e}"))?;
    read_body(&mut tls).await
}

/// Read the whole response (until close, capped), verify 2xx, return the body after
/// the header terminator — decoding `Transfer-Encoding: chunked` if present.
async fn read_body<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut tmp = [0u8; 16 * 1024];
    loop {
        let n = match s.read(&mut tmp).await {
            Ok(n) => n,
            // Servers that close without close_notify surface UnexpectedEof; treat it
            // as a normal end-of-stream since we read to close anyway.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read: {e}")),
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
        if out.len() > MAX_BODY {
            return Err("response too large".into());
        }
    }
    let sep = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let head = String::from_utf8_lossy(&out[..sep]).to_ascii_lowercase();
    let status = String::from_utf8_lossy(&out[..sep])
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or("bad status line")?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}"));
    }
    let body = out[sep + 4..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        dechunk(&body)
    } else {
        Ok(body)
    }
}

/// Decode an HTTP/1.1 chunked body (GitHub responds chunked). Best-effort: stops at
/// the terminating zero-length chunk or when the data runs out.
fn dechunk(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0usize;
    while i < body.len() {
        let line_end = body[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("chunk: no size CRLF")?;
        let size_line = String::from_utf8_lossy(&body[i..i + line_end]);
        // A chunk-size line may carry `;ext` extensions — take the hex before `;`.
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| "chunk: bad size")?;
        i += line_end + 2;
        if size == 0 {
            break;
        }
        if i + size > body.len() {
            return Err("chunk: truncated".into());
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size;
        if body.get(i..i + 2) == Some(b"\r\n") {
            i += 2;
        }
    }
    Ok(out)
}

/// Strip a leading `v`, drop any `-prerelease` / `+build` suffix, return the dotted
/// numeric core (e.g. "v0.8.0-rc1" → "0.8.0"). Never panics; junk → "0".
fn normalize(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix('v')
        .or_else(|| s.strip_prefix('V'))
        .unwrap_or(s);
    let core = s.split(['-', '+']).next().unwrap_or(s);
    if core.is_empty() {
        "0".to_string()
    } else {
        core.to_string()
    }
}

/// Compare two version references NUMERICALLY (never as strings — else "0.7.10" would
/// sort before "0.7.9"). Missing trailing parts count as 0.
fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let pa: Vec<u64> = normalize(a)
        .split('.')
        .map(|x| x.parse().unwrap_or(0))
        .collect();
    let pb: Vec<u64> = normalize(b)
        .split('.')
        .map(|x| x.parse().unwrap_or(0))
        .collect();
    let n = pa.len().max(pb.len());
    for i in 0..n {
        let x = pa.get(i).copied().unwrap_or(0);
        let y = pb.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            std::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    std::cmp::Ordering::Equal
}

/// True if `latest` is strictly newer than `current`.
fn is_newer(latest: &str, current: &str) -> bool {
    cmp(latest, current) == std::cmp::Ordering::Greater
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_v_and_suffix() {
        assert_eq!(normalize("v0.7.5"), "0.7.5");
        assert_eq!(normalize("0.8.0-rc1"), "0.8.0");
        assert_eq!(normalize("v1.2.3+build.9"), "1.2.3");
        assert_eq!(normalize("  V2.0  "), "2.0");
        assert_eq!(normalize(""), "0");
    }

    #[test]
    fn compare_is_numeric_not_lexical() {
        assert!(is_newer("0.7.10", "0.7.9")); // the classic string-compare trap
        assert!(is_newer("0.8.0", "0.7.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.7.5", "0.7.5"));
        assert!(!is_newer("0.7.5", "0.7.6"));
        assert!(!is_newer("v0.7.5", "0.7.5")); // tag form equals plain form
        assert!(is_newer("v0.7.6", "0.7.5"));
    }

    #[test]
    fn missing_parts_count_as_zero() {
        assert!(!is_newer("0.7", "0.7.0"));
        assert!(is_newer("0.7.1", "0.7"));
    }

    #[test]
    fn dechunk_reassembles() {
        // "Wiki" + "pedia" in two chunks, then the 0-terminator.
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw).unwrap(), b"Wikipedia");
    }
}
