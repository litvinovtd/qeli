//! CLI-only legal resources. Not part of lib.rs or the network/FFI hot path.
//! Packed data is decoded only for `licenses --file/--export`, never on VPN startup.
//! The bounded safe-Rust LZ4 block reader adds no system or Cargo dependency.
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::path::{Component, Path};

include!("embedded_license_files.rs");

fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid embedded license archive",
    )
}

/// Read a trusted generated LZ4 block, while rejecting malformed/oversized data.
/// Only the CLI module links this decoder; it is not part of lib.rs/FFI.
#[cold]
fn decode(data: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    const MAX_LEGAL_BYTES: usize = 16 * 1024 * 1024;
    if expected > MAX_LEGAL_BYTES {
        return Err(corrupt());
    }
    fn length(data: &[u8], cursor: &mut usize, seed: usize, limit: usize) -> io::Result<usize> {
        let mut result = seed;
        if seed == 15 {
            loop {
                let byte = *data.get(*cursor).ok_or_else(corrupt)?;
                *cursor += 1;
                result = result.checked_add(byte as usize).ok_or_else(corrupt)?;
                if result > limit {
                    return Err(corrupt());
                }
                if byte != 255 {
                    break;
                }
            }
        }
        Ok(result)
    }
    let mut output = Vec::new();
    output.try_reserve_exact(expected).map_err(|_| corrupt())?;
    let mut cursor = 0;
    while let Some(&token) = data.get(cursor) {
        cursor += 1;
        let literals = length(data, &mut cursor, (token >> 4) as usize, expected)?;
        let end = cursor.checked_add(literals).ok_or_else(corrupt)?;
        if output.len().checked_add(literals).ok_or_else(corrupt)? > expected {
            return Err(corrupt());
        }
        output.extend_from_slice(data.get(cursor..end).ok_or_else(corrupt)?);
        cursor = end;
        if cursor == data.len() {
            break;
        }
        let offset_end = cursor.checked_add(2).ok_or_else(corrupt)?;
        let bytes = data.get(cursor..offset_end).ok_or_else(corrupt)?;
        let offset = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        cursor = offset_end;
        let count = length(data, &mut cursor, (token & 15) as usize, expected)?
            .checked_add(4)
            .ok_or_else(corrupt)?;
        if offset == 0
            || offset > output.len()
            || output.len().checked_add(count).ok_or_else(corrupt)? > expected
        {
            return Err(corrupt());
        }
        // Increasing-order copy is required for overlapping LZ4 matches.
        for _ in 0..count {
            output.push(output[output.len() - offset]);
        }
    }
    if output.len() != expected {
        return Err(corrupt());
    }
    Ok(output)
}

#[cold]
fn unpack() -> io::Result<Vec<u8>> {
    let bytes = decode(PACKED, UNPACKED_LEN)?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != UNPACKED_SHA256 {
        return Err(corrupt());
    }
    Ok(bytes)
}

fn original(bytes: &[u8], offset: usize, length: usize) -> io::Result<&[u8]> {
    let end = offset.checked_add(length).ok_or_else(corrupt)?;
    bytes.get(offset..end).ok_or_else(corrupt)
}

pub fn run(file: Option<&str>, export: Option<&Path>, list: bool) -> io::Result<()> {
    if let Some(destination) = export {
        export_directory(destination)?;
        println!(
            "Exported {} original license resources to {}",
            FILES.len(),
            destination.display()
        );
    } else if let Some(name) = file {
        let (_, offset, length) =
            FILES
                .iter()
                .find(|(path, _, _)| *path == name)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "Unknown license resource; use licenses --list",
                    )
                })?;
        let bytes = unpack()?;
        io::stdout()
            .lock()
            .write_all(original(&bytes, *offset, *length)?)?;
    } else if list {
        let mut output = io::stdout().lock();
        for (name, _, _) in FILES {
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
    let bytes = unpack()?;
    // An existing directory or symlink is never accepted, even when empty.
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(destination)?;
    for (name, offset, length) in FILES {
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
        options
            .open(output)?
            .write_all(original(&bytes, *offset, *length)?)?;
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
        let bytes = unpack().unwrap();
        assert_eq!(FILES.len(), ORIGINALS.len());
        for ((name, offset, length), (source_name, source_bytes)) in FILES.iter().zip(ORIGINALS) {
            assert!(names.insert(name));
            assert_eq!(name, source_name);
            assert_eq!(original(&bytes, *offset, *length).unwrap(), *source_bytes);
            assert!(*length > 0);
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
        for (name, bytes) in ORIGINALS {
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

    #[test]
    fn bounded_decoder_handles_literals_overlap_and_malformed_blocks() {
        assert_eq!(decode(&[0x30, b'a', b'b', b'c'], 3).unwrap(), b"abc");
        assert_eq!(
            decode(&[0x10, b'a', 1, 0, 0x50, b'b', b'c', b'd', b'e', b'f'], 10).unwrap(),
            b"aaaaabcdef"
        );
        assert!(decode(&[0], 17 * 1024 * 1024).is_err());
        for bad in [
            &[0xf0][..],
            &[0x30, b'a'],
            &[0, 0, 0],
            &[0, 1, 0],
            &[0x10, b'a', 1],
            &[0x10, b'a', 1, 0],
        ] {
            assert!(decode(bad, 3).is_err());
        }
        assert!(original(b"abc", usize::MAX, 1).is_err());
        assert!(original(b"abc", 2, 2).is_err());
    }

    #[test]
    fn bounded_decoder_rejects_truncated_archive_without_panicking() {
        for end in [0, 1, 2, 16, PACKED.len() / 2, PACKED.len() - 1] {
            assert!(decode(&PACKED[..end], UNPACKED_LEN).is_err());
        }
        // A deterministic malformed-input sweep, bounded to small output buffers.
        let mut state = 0x1234_5678_u32;
        for size in 0..128 {
            let bytes: Vec<_> = (0..size)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            let _ = decode(&bytes, 256);
        }
    }
}
