//! Linux sysctl boundary. Tests replace it per thread; they never write host knobs.
pub(super) fn acquire(path: &str, value: &str, scope: &str) -> bool {
    #[cfg(test)]
    if let Some(result) = test_support::call(test_support::Operation::Acquire(path, value, scope)) {
        return result.is_ok();
    }
    #[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
    {
        crate::sysctl::acquire(path, value, scope)
    }
    #[cfg(not(all(target_os = "linux", any(feature = "client", feature = "server"))))]
    panic!("gateway sysctl acquire requires an isolated test backend");
}

pub(super) fn read(path: &str) -> std::io::Result<String> {
    #[cfg(test)]
    if let Some(result) = test_support::call(test_support::Operation::Read(path)) {
        return result;
    }
    #[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
    {
        std::fs::read_to_string(path)
    }
    #[cfg(not(all(target_os = "linux", any(feature = "client", feature = "server"))))]
    panic!("gateway sysctl read requires an isolated test backend");
}

pub(super) fn release(scope: &str) -> anyhow::Result<()> {
    #[cfg(test)]
    if let Some(result) = test_support::call(test_support::Operation::Release(scope)) {
        return result.map(|_| ()).map_err(Into::into);
    }
    #[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
    {
        crate::sysctl::release_scope(scope)
    }
    #[cfg(not(all(target_os = "linux", any(feature = "client", feature = "server"))))]
    panic!("gateway sysctl release requires an isolated test backend");
}

#[cfg(test)]
pub(super) mod test_support {
    use std::{cell::RefCell, io};
    pub(crate) enum Operation<'a> {
        Acquire(&'a str, &'a str, &'a str),
        Read(&'a str),
        Release(&'a str),
    }
    type Handler = Box<dyn FnMut(Operation<'_>) -> io::Result<String>>;
    thread_local! {
        static BACKEND: RefCell<Option<Handler>> = RefCell::new(None);
    }
    pub(super) fn call(op: Operation<'_>) -> Option<io::Result<String>> {
        BACKEND.with(|slot| slot.borrow_mut().as_mut().map(|run| run(op)))
    }
    pub(crate) fn with_sysctls<T>(
        handler: impl FnMut(Operation<'_>) -> io::Result<String> + 'static,
        run: impl FnOnce() -> T,
    ) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BACKEND.with(|slot| *slot.borrow_mut() = None);
            }
        }
        BACKEND.with(|slot| {
            assert!(slot.borrow().is_none(), "nested sysctl override");
            *slot.borrow_mut() = Some(Box::new(handler));
        });
        let _reset = Reset;
        run()
    }
}
