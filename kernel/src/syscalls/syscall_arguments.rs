use core::convert::TryFrom;

/// The raw registers from which syscall arguments are extracted.
#[repr(C)]
#[derive(Debug)]
pub struct SyscallRegisters {
    pub number: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub arg6: u64,
}

/// ----- Syscall Argument Structures -----

/// sys_exit: exit(status: i64)
pub struct SysExitArgs {
    pub status: i64,
}

impl TryFrom<&SyscallRegisters> for SysExitArgs {
    type Error = ();
    fn try_from(regs: &SyscallRegisters) -> Result<Self, Self::Error> {
        Ok(Self {
            status: regs.arg1 as i64,
        })
    }
}

/// sys_print: print(message_ptr: *const u8)
pub struct SysPrintArgs {
    pub message_ptr: *const u8,
}

impl TryFrom<&SyscallRegisters> for SysPrintArgs {
    type Error = ();
    fn try_from(regs: &SyscallRegisters) -> Result<Self, Self::Error> {
        Ok(Self {
            message_ptr: regs.arg1 as *const u8,
        })
    }
}

/// sys_nanosleep_64: nanosleep(duration: u64)
pub struct SysNanosleepArgs {
    pub duration: u64,
}

impl TryFrom<&SyscallRegisters> for SysNanosleepArgs {
    type Error = ();
    fn try_from(regs: &SyscallRegisters) -> Result<Self, Self::Error> {
        Ok(Self {
            duration: regs.arg1,
        })
    }
}

/// sys_fork: no arguments from registers in this case.
pub struct SysForkArgs;

impl TryFrom<&SyscallRegisters> for SysForkArgs {
    type Error = ();
    fn try_from(_regs: &SyscallRegisters) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

/// sys_mmap: mmap(addr, length, prot, flags, fd, offset)
pub struct SysMmapArgs {
    pub addr: u64,
    pub length: u64,
    pub prot: u64,
    pub flags: u64,
    pub fd: i64,
    pub offset: u64,
}

impl TryFrom<&SyscallRegisters> for SysMmapArgs {
    type Error = ();
    fn try_from(regs: &SyscallRegisters) -> Result<Self, Self::Error> {
        Ok(Self {
            addr: regs.arg1,
            length: regs.arg2,
            prot: regs.arg3,
            flags: regs.arg4,
            fd: regs.arg5 as i64,
            offset: regs.arg6,
        })
    }
}

/// sys_wait: wait(pid: u32)
pub struct SysWaitArgs {
    pub pid: u32,
}

impl TryFrom<&SyscallRegisters> for SysWaitArgs {
    type Error = ();
    fn try_from(regs: &SyscallRegisters) -> Result<Self, Self::Error> {
        Ok(Self {
            pid: regs.arg1 as u32,
        })
    }
}

/// sys_munmap: munmap(addr, length)
pub struct SysMunmapArgs {
    pub addr: u64,
    pub length: u64,
}

impl TryFrom<&SyscallRegisters> for SysMunmapArgs {
    type Error = ();
    fn try_from(regs: &SyscallRegisters) -> Result<Self, Self::Error> {
        Ok(Self {
            addr: regs.arg1,
            length: regs.arg2,
        })
    }
}

/// sys_open: open(path: *const u8, flags: u64, mode: u64)
pub struct SysOpenArgs {
    pub path: *const u8,
    pub flags: u64,
    pub mode: u64,
}

impl TryFrom<&SyscallRegisters> for SysOpenArgs {
    type Error = ();
    fn try_from(regs: &SyscallRegisters) -> Result<Self, Self::Error> {
        Ok(Self {
            path: regs.arg1 as *const u8,
            flags: regs.arg2,
            mode: regs.arg3,
        })
    }
}

