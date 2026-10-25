//! Error values shared across kernel/user boundaries.
//!
//! Kernel code keeps errors typed internally.  A syscall converts an error to
//! the conventional negative errno representation only at the ABI boundary.

/// Errors that can be returned to userspace by a syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Errno {
    BadFileDescriptor = 9,
    NoChild = 10,
    OutOfMemory = 12,
    Fault = 14,
    InvalidArgument = 22,
    TooManyOpenFiles = 24,
    AddressInUse = 98,
    NotSocket = 88,
    OperationNotSupported = 95,
    NoDevice = 19,
    IllegalByteSequence = 84,
    NoSuchProcess = 3,
    NotImplemented = 38,
}

impl Errno {
    /// Encode this errno in the unsigned syscall return register.
    pub const fn as_syscall_return(self) -> u64 {
        (-(self as i64)) as u64
    }
}

pub type SyscallResult<T> = Result<T, Errno>;
