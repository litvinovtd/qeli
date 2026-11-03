//! CLI-only legal resources. Not part of lib.rs or the network/FFI hot path.
//! No codec/dependency or privilege is required to read the original text bytes.
use std::io::{self, Write};
use std::path::{Component, Path};

include!("embedded_license_files.rs");

pub fn run(file: Option<&str>, export: Option<&Path>, list: bool) -> io::Result<()> {
    if let Some(destination) = export {
        export_directory(destination)?;
        println!(
            "Exported {} original license resources to {}",
            FILES.len(),
            destination.display()
        );
    } else if let Some(name) = file {
        let bytes = FILES
            .iter()
            .find(|(path, _)| *path == name)
            .map(|(_, bytes)| *bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Unknown license resource; use licenses --list",
                )
            })?;
        io::stdout().lock().write_all(bytes)?;
    } else if list {
        let mut output = io::stdout().lock();
        for (name, _) in FILES {
            writeln!(output, "{name}")?;
        }
    } else {
        println!("Qeli {} — AGPL-3.0-only", env!("CARGO_PKG_VERSION"));
        println!("Source: https://github.com/litvinovtd/qeli");
        println!(
            "{} original license/notice/index resources are embedded in this binary.",
            FILES.len()
        );
        println!("licenses --list                 List resource paths");
        println!("licenses --file PATH            Read one complete original resource");
        println!("licenses --export NEW_DIRECTORY Export the complete bundle, without overwriting");
        println!("Core license: licenses --file rust/Qeli-AGPL-3.0.txt");
        println!(
            "Inventory includes build/test/other-target packages; presence does not imply linkage."
        );
    }
    Ok(())
}

fn export_directory(destination: &Path) -> io::Result<()> {
    // An existing directory or symlink is never accepted, even when empty.
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(destination)?;
    for (name, bytes) in FILES {
        let relative = Path::new(name);
        if !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid embedded resource path",
            ));
        }
        let output = destination.join(relative);
        std::fs::create_dir_all(
            output
                .parent()
                .expect("embedded relative path has a parent"),
        )?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(output)?.write_all(bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn catalogue_has_unique_safe_paths_and_complete_core_license() {
        let mut names = HashSet::new();
        for (name, bytes) in FILES {
            assert!(names.insert(name));
            assert!(!bytes.is_empty());
            assert!(Path::new(name)
                .components()
                .all(|c| matches!(c, Component::Normal(_))));
        }
        assert!(names.contains(&"rust/INDEX.tsv"));
        assert!(names.contains(&"rust/Qeli-AGPL-3.0.txt"));
        assert!(names.contains(&"rust/toolchains/INDEX.tsv"));
    }

    #[test]
    fn export_preserves_every_byte_and_refuses_existing_destinations() {
        let root = std::env::temp_dir().join(format!(
            "qeli-license-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let destination = root.join("original-texts");
        export_directory(&destination).unwrap();
        for (name, bytes) in FILES {
            assert_eq!(std::fs::read(destination.join(name)).unwrap(), *bytes);
        }
        assert_eq!(
            export_directory(&destination).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let canary = root.join("do-not-touch");
        std::fs::write(&canary, b"canary").unwrap();
        assert!(export_directory(&canary).is_err());
        assert_eq!(std::fs::read(&canary).unwrap(), b"canary");
        std::fs::remove_dir_all(root).unwrap();
    }
}
