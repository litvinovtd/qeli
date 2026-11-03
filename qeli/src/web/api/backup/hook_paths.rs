//! Conservative protection of literal file references in trusted shell hooks.
//!
//! This is not a shell interpreter: variables constructed entirely outside a literal
//! managed path, runtime `cd`, and files read inside external scripts are not discoverable.
//! Keep executable hooks and their dependencies outside the managed backup tree.
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

pub(super) struct HookFiles {
    root: PathBuf,
    resolved_root: Option<PathBuf>,
    names: HashSet<String>,
    all: bool,
}

impl HookFiles {
    pub(super) fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            resolved_root: std::fs::canonicalize(root).ok(),
            names: HashSet::new(),
            all: false,
        }
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        self.all || self.names.contains(name)
    }

    pub(super) fn add_command(&mut self, command: &str) {
        // Retain the raw literal scan too: arbitrarily nested interpreter -c
        // expressions need not fit the shallow quote-aware word inspection below.
        for fragment in command.split(|c: char| {
            c.is_whitespace() || matches!(c, '\'' | '"' | ';' | '&' | '|' | '(' | ')' | '<' | '>')
        }) {
            for (index, _) in fragment.match_indices('/') {
                self.add_path(Path::new(&fragment[index..]));
            }
        }
        for literal in literal_words(command) {
            // Also inspect an interpreter's quoted -c expression. The intact literal
            // remains a candidate, preserving filenames containing spaces.
            for word in std::iter::once(literal.clone()).chain(literal_words(&literal)) {
                // Include assignment values and paths embedded in interpreter expressions.
                // Scan at every slash: an outside alias may resolve into the managed tree.
                self.add_path(Path::new(&word));
                for (index, _) in word.match_indices('/') {
                    self.add_path(Path::new(&word[index..]));
                }
            }
        }
    }

    fn protect(&mut self, path: &Path) {
        let relative = match path.strip_prefix(&self.root) {
            Ok(relative) => relative,
            Err(_) => {
                let Some(root) = &self.resolved_root else {
                    return;
                };
                let Ok(relative) = path.strip_prefix(root) else {
                    return;
                };
                relative
            }
        };
        let top = relative.components().find_map(|part| match part {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        });
        match top {
            // An unknown top-level name can refer to any archive entry. Refuse publication.
            Some(name) if name.contains(['$', '*', '?', '[', '`']) => self.all = true,
            Some(name) => {
                self.names.insert(name);
            }
            None => self.all = true,
        }
    }

    fn add_path(&mut self, path: &Path) {
        if path.as_os_str().is_empty() {
            return;
        }
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            let Ok(cwd) = std::env::current_dir() else {
                self.all = true;
                return;
            };
            cwd.join(path)
        };
        // Protect both the alias entry and the eventual target. Normalizing before
        // canonicalization alone is incorrect when a symlink precedes `..`.
        self.protect(&absolute);
        self.protect(&normalize_absolute(&absolute));
        if let Some(resolved) = resolve_existing_prefix(&absolute) {
            self.protect(&normalize_absolute(&resolved));
        }
    }
}

fn normalize_absolute(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn resolve_existing_prefix(path: &Path) -> Option<PathBuf> {
    // A hook may name a file that does not exist yet. Resolve the existing parent
    // too, so an outside directory symlink cannot hide that future managed file.
    for ancestor in path.ancestors() {
        if let Ok(mut resolved) = std::fs::canonicalize(ancestor) {
            resolved.push(path.strip_prefix(ancestor).ok()?);
            return Some(resolved);
        }
    }
    None
}

fn literal_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => word.push(c),
            (_, '\\') => {
                if let Some(next) = chars.next() {
                    // In double quotes the shell only consumes selected escapes.
                    if quote == Some('"') && !matches!(next, '$' | '`' | '"' | '\\' | '\n') {
                        word.push('\\');
                    }
                    if next != '\n' {
                        word.push(next);
                    }
                }
            }
            (None, '\'' | '"') => quote = Some(c),
            (None, c)
                if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>') =>
            {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            _ => word.push(c),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    fn collected(command: &str) -> HookFiles {
        let mut files = HookFiles::new(Path::new("/etc/qeli"));
        files.add_command(command);
        files
    }
    #[test]
    fn parent_alias_cannot_hide_the_executed_file() {
        assert!(collected("sh /etc/qeli/../qeli/owned.txt").contains("owned.txt"));
    }
    #[test]
    fn nested_parent_protects_both_entries() {
        let files = collected("sh /etc/qeli/scripts/../owned.txt");
        assert!(files.contains("scripts"));
        assert!(files.contains("owned.txt"));
    }
    #[test]
    fn outside_lexical_alias_and_repeated_slashes() {
        assert!(collected("sh /etc/../etc//qeli/owned.txt").contains("owned.txt"));
        assert!(collected("sh //etc/qeli/./owned.txt").contains("owned.txt"));
    }
    #[test]
    fn quoted_and_escaped_spaces_are_one_path() {
        for cmd in [
            "sh '/etc/qeli/my scripts/up.txt'",
            "sh \"/etc/qeli/my scripts/up.txt\"",
            r"sh /etc/qeli/my\ scripts/up.txt",
        ] {
            assert!(collected(cmd).contains("my scripts"), "{cmd}");
        }
    }
    #[test]
    fn concatenated_shell_quotes() {
        assert!(collected("sh /etc/'qeli'/\"my scripts\"/up.txt").contains("my scripts"));
    }
    #[test]
    fn compound_commands_substitution_and_redirection() {
        let files = collected("true&&sh /etc/qeli/a.txt; . /etc/qeli/b.txt | cat < /etc/qeli/c.txt; echo $(cat /etc/qeli/d.txt)");
        for name in ["a.txt", "b.txt", "c.txt", "d.txt"] {
            assert!(files.contains(name));
        }
    }
    #[test]
    fn interpreter_inline_command_remains_protected() {
        assert!(collected("sh -c 'sh /etc/qeli/owned.txt; echo ready'").contains("owned.txt"));
    }
    #[test]
    fn nested_inline_expressions_preserve_raw_literal_protection() {
        assert!(
            collected("sh -c \"sh -c 'sh /etc/qeli/owned.txt; echo ready'\"").contains("owned.txt")
        );
    }
    #[test]
    fn dynamic_top_level_and_tree_read_block_all_entries() {
        for cmd in [
            "sh /etc/qeli/$SCRIPT",
            "sh /etc/qeli/*.txt",
            "cat /etc/qeli/[ab].txt",
            "find /etc/qeli",
        ] {
            assert!(collected(cmd).contains("any.txt"), "{cmd}");
        }
    }
    #[test]
    fn known_subdirectory_with_dynamic_leaf_blocks_only_that_entry() {
        let files = collected("sh /etc/qeli/scripts/$SCRIPT");
        assert!(files.contains("scripts"));
        assert!(!files.contains("unrelated.txt"));
    }
    #[test]
    fn unrelated_external_hook_does_not_block_restore() {
        let files = collected("/opt/site/up.sh --config /etc/qeli-other/data.txt");
        assert!(!files.contains("server.conf"));
        assert!(!files.contains("data.txt"));
    }
    #[test]
    fn assignment_and_inline_expression_paths() {
        assert!(collected("SCRIPT=/etc/qeli/owned.txt; sh $SCRIPT").contains("owned.txt"));
    }
    #[cfg(unix)]
    #[test]
    fn symlink_aliases_existing_missing_and_parent_paths() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("qeli-hook-paths-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let root = base.join("managed");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("scripts")).unwrap();
        std::fs::write(root.join("owned.txt"), "trusted").unwrap();
        symlink(&root, base.join("outside")).unwrap();
        symlink(root.join("scripts"), root.join("alias")).unwrap();
        let mut files = HookFiles::new(&root);
        files.add_command(&format!("sh {}/outside/owned.txt", base.display()));
        assert!(files.contains("owned.txt"));
        files.add_command(&format!("sh {}/outside/future.txt", base.display()));
        assert!(files.contains("future.txt"));
        files.add_command(&format!("sh {}/alias/../owned.txt", root.display()));
        assert!(files.contains("alias"));
        assert!(files.contains("owned.txt"));
        symlink(&root, base.join("managed-alias")).unwrap();
        let mut aliased_root = HookFiles::new(&base.join("managed-alias"));
        aliased_root.add_command(&format!("sh {}/outside/owned.txt", base.display()));
        assert!(aliased_root.contains("owned.txt"));
        std::fs::remove_dir_all(base).unwrap();
    }
}
