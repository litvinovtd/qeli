use std::path::{Path, PathBuf};

pub const ALLOWED_LOG_DIRS: &[&str] = &["/var/log/qeli"];
pub const ALLOWED_CONFIG_DIRS: &[&str] = &["/etc/qeli"];
pub const ALLOWED_TLS_DIRS: &[&str] = &["/etc/qeli", "/etc/letsencrypt"];

/// Resolve `path` and ensure it points to a regular file inside one of `allowed`.
/// Used for reading an existing log file or writing to an already-loaded config.
pub fn validate_in_whitelist(path: &str, allowed: &[&str]) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("path is empty".into());
    }
    let canon = Path::new(path)
        .canonicalize()
        .map_err(|e| format!("cannot resolve '{}': {}", path, e))?;
    if !canon.is_file() {
        return Err(format!("not a regular file: {}", canon.display()));
    }
    for dir in allowed {
        let dir_canon = Path::new(dir)
            .canonicalize()
            .unwrap_or_else(|_| Path::new(dir).to_path_buf());
        if canon.starts_with(&dir_canon) {
            return Ok(canon);
        }
    }
    Err(format!(
        "'{}' is outside allowed directories {:?}",
        canon.display(),
        allowed
    ))
}

/// Cheap syntactic check for a user-supplied path field (e.g. `logging.file`)
/// whose target file may not yet exist. Rejects relative paths, `..`, and any
/// path not prefixed by one of `allowed` directories.
pub fn validate_path_field(path: &str, allowed: &[&str]) -> Result<(), String> {
    if path.is_empty() {
        return Ok(());
    }
    if !path.starts_with('/') {
        return Err(format!("must be absolute: {}", path));
    }
    if path.split('/').any(|seg| seg == "..") {
        return Err(format!("must not contain '..': {}", path));
    }
    let ok = allowed.iter().any(|d| {
        let prefix = format!("{}/", d.trim_end_matches('/'));
        path.starts_with(&prefix)
    });
    if !ok {
        return Err(format!("must be inside one of {:?}: {}", allowed, path));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_tls_paths_include_lets_encrypt_without_widening_config_paths() {
        let cert = "/etc/letsencrypt/live/vpn.example.com/fullchain.pem";
        assert!(validate_path_field(cert, ALLOWED_TLS_DIRS).is_ok());
        assert!(validate_path_field(cert, ALLOWED_CONFIG_DIRS).is_err());
        assert!(validate_path_field("/etc/qeli/web-tls-key.pem", ALLOWED_TLS_DIRS).is_ok());
        assert!(validate_path_field("/etc/letsencrypt/../shadow", ALLOWED_TLS_DIRS).is_err());
        assert!(validate_path_field("/tmp/key.pem", ALLOWED_TLS_DIRS).is_err());
    }
}
