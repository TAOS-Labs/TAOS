use core::u64;

// Open flags
const O_RDONLY: u32 = 0x0;
const O_WRONLY: u32 = 0x1;
const O_WR: u32 = 0x2;

const O_CREAT: u32 = 0x200;	
const O_TRUNC: u32 = 0x400;

// For now, ignore mode (universal access permissions)
pub fn sys_open(pathname: *const u8, flags: u32, mode: u16) -> u64 {
  

  // Error; corresponds to -1 signed 
  u64::MAX 
}

pub fn sys_creat(pathname: *const u8, mode: u16) -> u64 {
  sys_open(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode)
}