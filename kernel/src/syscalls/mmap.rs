use alloc::sync::Arc;
use bitflags::bitflags;
use x86_64::structures::paging::{OffsetPageTable, Page, PageTable, PageTableFlags, Size4KiB};

use crate::{
    events::{current_running_event_info, EventInfo},
    memory::{
        mm::{AnonVmArea, VmAreaFlags},
        HHDM_OFFSET,
    },
    processes::process::PROCESS_TABLE,
    serial_println,
};

// See https://www.man7.org/linux/man-pages/man2/mmap.2.html
bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MmapFlags: u64 {
        const MAP_SHARED = 1 << 0;
        const MAP_SHARED_VALIDATE = 1 << 1;
        const MAP_PRIVATE = 1 << 2;
        const MAP_32BIT = 1 << 3;
        const MAP_ANONYMOUS = 1 << 4;
        const MAP_ANON = 1 << 4;
        const MAP_DENYWRITE = 1 << 5;
        const MAP_EXECUTABLE = 1 << 6;
        const MAP_FILE = 1 << 7;
        const MAP_FIXED = 1 << 8;
        const MAP_FIXED_NOREPLACE = 1 << 9;
        const MAP_GROWSDOWN = 1 << 10;
        const MAP_HUGETLB = 1 << 11;
        const MAP_HUGE_2MB = 1 << 12;
        const MAP_HUGE_1GB = 1 << 13;
        const MAP_LOCKED = 1 << 14;
        const MAP_NONBLOCK = 1 << 15;
        const MAP_NORESERVE = 1 << 16;
        const MAP_POPULATE = 1 << 17;
        const MAP_STACK = 1 << 18;
        const MAP_SYNC = 1 << 19;
        const MAP_UNINITIALIZED = 1 << 20;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtFlags(u64);

impl Default for ProtFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtFlags {
    pub const PROT_EXEC: u64 = 1 << 0;
    pub const PROT_READ: u64 = 1 << 1;
    pub const PROT_WRITE: u64 = 1 << 2;
    pub const PROT_NONE: u64 = 1 << 3;

    pub const fn new() -> Self {
        ProtFlags(0)
    }

    // creates ProtFlags with inputted flags
    pub const fn with_flags(self, flag: u64) -> Self {
        ProtFlags(self.0 | flag)
    }

    // Checks if ProtFlags contains input flags
    pub const fn contains(self, flag: u64) -> bool {
        (self.0 & flag) != 0
    }

    // returns the ProtFlags
    pub const fn bits(self) -> u64 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmapErrors {
    EACCES,
    EAGAIN,
    EBADF,
    EEXIST,
    EINVAL,
    ENFILE,
    ENODEV,
    ENOMEM,
    EOVERFLOW,
    EPERM,
    ETXTBSY,
    SIGSEGV,
    SIGBUS,
}

pub fn protection_to_pagetable_flags(prot: u64) -> PageTableFlags {
    let mut flags = PageTableFlags::empty();

    if prot & ProtFlags::PROT_READ != 0 {
        flags |= PageTableFlags::PRESENT;
    }
    if prot & ProtFlags::PROT_WRITE != 0 {
        flags |= PageTableFlags::WRITABLE | PageTableFlags::PRESENT;
    }
    if prot & ProtFlags::PROT_EXEC == 0 {
        flags |= PageTableFlags::NO_EXECUTE | PageTableFlags::PRESENT;
    }

    flags
}

pub fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: i64, offset: u64) -> u64 {
    // we will currently completely ignore user address requests and do whatever we want
    if len == 0 {
        serial_println!("Zero length mapping");
        panic!();
        // return something
    }
    serial_println!("Fd is {}", fd);
    let event: EventInfo = current_running_event_info();
    let pid = event.pid;
    // for testing we hardcode to one for now
    let process_table = PROCESS_TABLE.write();
    let process = process_table
        .get(&pid)
        .expect("Could not get pcb from process table");
    let pcb = process.pcb.get();
    let begin_addr = unsafe { (*pcb).mmap_address };
    // We must return the original beginning address while adjusting the value of MMAP_ADDR
    // for the next calls to MMAP
    let addr_to_return = begin_addr;
    let anon_vma = AnonVmArea::new();

    if begin_addr + len > (*HHDM_OFFSET).as_u64() {
        serial_println!("Ran out of virtual memory for mmap call.");
        return 0;
    }
    unsafe {
        (*pcb).mm.with_vma_tree_mutable(|tree| {
            let _ = (*pcb).mm.insert_vma(
                tree,
                begin_addr,
                begin_addr + len,
                Arc::new(anon_vma),
                VmAreaFlags::WRITABLE,
                true,
            );
        })
    }

    serial_println!("Finished mmap call");
    addr_to_return
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::processes::MMAP_ANON_SIMPLE,
        events::schedule_process,
        processes::process::{create_process, PCB, PROCESS_TABLE},
    };

    fn setup() -> (u32, *mut PCB) {
        let pid = create_process(MMAP_ANON_SIMPLE);
        let process_table = PROCESS_TABLE.write();
        let process = process_table
            .get(&pid)
            .expect("Could not get pcb from process table");
        (pid, process.pcb.get())
    }

    // #[test_case]
    fn test_basic_anon_mmap() {
        let p = setup();
        let pid = p.0;
        let pcb = p.1;
        unsafe {
            let mmap_addr_before: u64 = (*pcb).mmap_address;
            schedule_process(pid);
            assert!(true);
        }
    }

    // #[test_case]
    fn test_two_anon_mmap() {
        let p = setup();
        let pid = p.0;
        let pcb = p.1;
        unsafe {
            let mmap_addr_before: u64 = (*pcb).mmap_address;

            schedule_process(pid);
            schedule_process(pid);
        }
        assert!(true);
    }
}
