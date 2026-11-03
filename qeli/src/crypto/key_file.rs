//! Bounded reads of persisted 32-byte secrets. Existing regular-file symlinks remain usable.
use std::io::{self, Read};
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) fn read(path: &Path) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A FIFO must not park a supervisor/CLI before its type can be checked.
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A dangling operator link is not an absent key to replace.
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "key path exists but cannot be opened",
                    ))
                }
            }
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "key must be a regular file containing exactly 32 bytes",
        ));
    }
    read_exact_key(file).map(Some)
}

fn read_exact_key(reader: impl Read) -> io::Result<Zeroizing<[u8; 32]>> {
    // A concurrent append must not turn this into an unbounded allocation/read.
    let mut bytes = Zeroizing::new([0u8; 33]);
    let mut length = 0;
    let mut bounded = reader.take(33);
    while length < bytes.len() {
        match bounded.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(n) => length += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if length != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "key must contain exactly 32 bytes",
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_secret_read_is_bounded_and_rejects_short_or_growing_inputs() {
        struct NeverEnding(usize);
        impl Read for NeverEnding {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.0 += bytes.len();
                assert!(self.0 <= 33, "must never consume more than 33 secret bytes");
                bytes.fill(7);
                Ok(bytes.len())
            }
        }
        assert!(read_exact_key(NeverEnding(0)).is_err());
        for n in [0, 1, 31, 33, 4096] {
            assert!(read_exact_key(io::Cursor::new(vec![7; n])).is_err());
        }
        assert_eq!(*read_exact_key(io::Cursor::new([7; 32])).unwrap(), [7; 32]);
    }
    #[cfg(unix)]
    #[test]
    fn special_and_dangling_keys_are_refused_without_replacement() {
        use std::os::unix::fs::{symlink, FileTypeExt};
        let dir = std::env::temp_dir().join(format!(
            "qeli-key-files-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("key");
        assert!(read(&path).unwrap().is_none());
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_fifo());
        std::fs::remove_file(&path).unwrap();
        symlink(dir.join("missing"), &path).unwrap();
        assert!(read(&path).is_err());
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::write(dir.join("missing"), [9; 32]).unwrap();
        assert_eq!(*read(&path).unwrap().unwrap(), [9; 32]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
