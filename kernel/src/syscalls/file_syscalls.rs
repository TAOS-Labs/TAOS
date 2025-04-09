
use core::ffi::CStr;

use super::{syscall_arguments::*, syscall_handlers::SysResult};
use alloc::{slice, str};
use x86_64::structures::paging::{OffsetPageTable, PageTable, PageTableFlags, PhysFrame};

use crate::{
    events::{current_running_event_info, schedule_process_on},
    filesys::{FileSystem, FsError::*, FILESYSTEM},
    memory::{
        frame_allocator::{alloc_frame, with_buddy_frame_allocator},
        mm::Mm,
        HHDM_OFFSET,
    },
    processes::{
        process::{ProcessState, UnsafePCB, NEXT_PID, PCB, PROCESS_TABLE},
        registers::NonFlagRegisters,
    },
    serial_println,
};

pub async fn sys_open(args: SysOpenArgs) -> SysResult<u64> {
    // TODO: Add pointer validation system

    let c_str = unsafe { CStr::from_ptr(args.path as *const i8) };
    let path = c_str.to_str().expect("Invalid UTF-8 string");

    let file = FILESYSTEM
        .get()
        .expect("Could not get filesystem")
        .lock()
        .open_file(path)
        .await;

    let ret = match file {
        Ok(value) => value,
        Err(err) => {
            match err {
                IOError => 
            }
        }
    }

    return Ok(file as u64);
}
