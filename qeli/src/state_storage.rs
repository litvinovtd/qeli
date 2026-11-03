//! Trusted, descriptor-relative storage shared by privileged recovery journals.
pub(crate) mod journal_file;
pub(crate) mod state_dir;

/// One machine-local journal root for routes, DNS, sysctls and server firewall.
/// The caller must still open it with `state_dir::Directory`: an environment
/// override is not permission to follow links or adopt writable/foreign storage.
pub(crate) fn default_state_dir() -> std::path::PathBuf {
    resolve_state_dir(std::env::var_os("STATE_DIRECTORY"))
}

fn resolve_state_dir(value: Option<std::ffi::OsString>) -> std::path::PathBuf {
    value
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/qeli"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_root_uses_one_override_and_preserves_the_packaged_default() {
        for value in [None, Some("".into())] {
            assert_eq!(
                resolve_state_dir(value),
                std::path::Path::new("/var/lib/qeli")
            );
        }
        assert_eq!(
            resolve_state_dir(Some("/tmp/lib/qeli".into())),
            std::path::Path::new("/tmp/lib/qeli")
        );
        // Do not canonicalize or silently repair invalid paths. The trusted
        // descriptor-relative opener must reject them before creating anything.
        for path in ["relative", "/tmp/../state", "/tmp/linked/state"] {
            assert_eq!(
                resolve_state_dir(Some(path.into())),
                std::path::Path::new(path)
            );
        }
    }
}
