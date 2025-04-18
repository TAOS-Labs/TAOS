use core::u64;

use crate::processes::process::pawait;

use super::{FileSystem, OpenFlags, FILESYSTEM};
use core::ffi::CStr;

// For now, ignore mode (universal access permissions)
pub fn sys_open(pathname: *const i8, flags: u32, mode: u16) -> u64 {
  let path_str = unsafe {
    match CStr::from_ptr(pathname).to_str() {
        Ok(v) => v,
        Err(e) => {
          return u64::MAX;  // TODO set errno
        },
    }
  };

  let open_flags = match OpenFlags::from_bits(flags) {
    Some(of) => of,
    None => {
      return u64::MAX;
    }
  };

  let mut filelock = FILESYSTEM.get()
  .expect("Filesystem not initialized")
  .lock();

  pawait(filelock.open_file(path_str, open_flags));

  // Error; corresponds to -1 signed 
  u64::MAX 
}

pub fn sys_creat(pathname: *const i8, mode: u16) -> u64 {
  let flags = (OpenFlags::O_CREAT | OpenFlags::O_WRONLY | OpenFlags::O_TRUNC).bits();
  sys_open(pathname, flags, mode)
}