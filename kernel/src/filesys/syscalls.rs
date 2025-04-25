use core::ffi::CStr;

use crate::syscalls::syscall_handlers::ConstUserPtr;

use super::{FileSystem, OpenFlags, FILESYSTEM};

// For now, ignore mode (universal access permissions)
pub async fn sys_open(pathname: ConstUserPtr<i8>, flags: u32, _mode: u16) -> u64 {
    let path_str = unsafe {
        match CStr::from_ptr(pathname.0).to_str() {
            Ok(v) => v,
            Err(_) => {
                return u64::MAX; // TODO set errno
            }
        }
    };

    let open_flags = match OpenFlags::from_bits(flags) {
        Some(of) => of,
        None => {
            return u64::MAX;
        }
    };

    let mut filelock = FILESYSTEM
        .get()
        .expect("Filesystem not initialized")
        .lock()
        .await;

    match (*filelock).open_file(path_str, open_flags).await {
        Ok(fd) => fd as u64,
        Err(_) => u64::MAX,
    }
}

pub async fn sys_creat(pathname: ConstUserPtr<i8>, mode: u16) -> u64 {
    let flags = (OpenFlags::O_CREAT | OpenFlags::O_WRONLY | OpenFlags::O_TRUNC).bits();
    sys_open(pathname, flags, mode).await
}
