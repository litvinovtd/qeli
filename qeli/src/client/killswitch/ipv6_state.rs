//! Positive evidence that the IPv6 module was loaded with all functionality disabled.
//! Interface-level disable_ipv6 and empty address inventories are weaker observations;
//! neither permits bypassing an unavailable firewall ownership inventory.
use std::io::Read;

const DISABLE: &str = "/sys/module/ipv6/parameters/disable";
const LIMIT: u64 = 16;

pub(crate) fn globally_disabled() -> bool {
    #[cfg(test)]
    if let Some(disabled) = test_support::override_value() {
        return disabled;
    }
    std::fs::File::open(DISABLE).is_ok_and(read_disabled)
}

fn read_disabled(reader: impl Read) -> bool {
    let mut bytes = Vec::new();
    reader.take(LIMIT + 1).read_to_end(&mut bytes).is_ok() && (bytes == b"1" || bytes == b"1\n")
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::Cell;
    thread_local! {
        static DISABLED: Cell<Option<bool>> = const { Cell::new(None) };
    }
    pub(super) fn override_value() -> Option<bool> {
        DISABLED.with(Cell::get)
    }
    pub(crate) fn with_disabled<T>(disabled: bool, run: impl FnOnce() -> T) -> T {
        struct Reset(Option<bool>);
        impl Drop for Reset {
            fn drop(&mut self) {
                DISABLED.with(|slot| slot.set(self.0));
            }
        }
        let _reset = Reset(DISABLED.with(|slot| slot.replace(Some(disabled))));
        run()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_kernel_disabled_value_is_positive_evidence() {
        for bytes in [b"1".as_slice(), b"1\n"] {
            assert!(read_disabled(bytes));
        }
        for bytes in [
            b"".as_slice(),
            b"0\n",
            b"Y\n",
            b"true",
            b"01",
            b" 1",
            b"1\n0",
            b"1\0",
            b"1\xff",
            b"1\ntruncated",
            b"1                ",
        ] {
            assert!(!read_disabled(bytes), "{bytes:?}");
        }
    }
    #[test]
    fn read_failure_including_after_a_positive_prefix_is_not_evidence() {
        struct Fail;
        impl Read for Fail {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        }
        assert!(!read_disabled(Fail));
        assert!(!read_disabled(b"1\n".as_slice().chain(Fail)));
    }
    #[test]
    fn excessive_input_is_bounded_and_not_evidence() {
        struct Endless(usize);
        impl Read for Endless {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.0 += bytes.len();
                bytes.fill(b'1');
                Ok(bytes.len())
            }
        }
        let mut reader = Endless(0);
        assert!(!read_disabled(&mut reader));
        assert_eq!(reader.0, LIMIT as usize + 1);
    }
}
