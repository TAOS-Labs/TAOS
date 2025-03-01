use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{
    registers::control::Cr3,
    structures::paging::{OffsetPageTable, Page, PageTable, PageTableFlags, Size4KiB},
    VirtAddr,
};

use crate::{
    constants::{memory::PAGE_SIZE, syscalls::START_MMAP_ADDRESS},
    events::{current_running_event_info, EventInfo},
    interrupts::x2apic,
    memory::{paging::create_not_present_mapping, HHDM_OFFSET, KERNEL_MAPPER},
    processes::process::PROCESS_TABLE,
    serial_println,
};

static MMAP_ADDR: Mutex<u64> = Mutex::new(START_MMAP_ADDRESS);

#[derive(Clone, Debug)]
pub struct MmapCall {
    pub start: u64,
    pub end: u64,
    pub fd: i64,
    pub offset: u64,
    pub loaded: Vec<bool>,
}

impl MmapCall {
    pub fn new(start: u64, end: u64, fd: i64, offset: u64) -> Self {
        MmapCall {
            start,
            end,
            fd,
            offset,
            loaded: Vec::new(),
        }
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

// See https://www.man7.org/linux/man-pages/man2/mmap.2.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmapFlags(u64);

impl Default for MmapFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl MmapFlags {
    pub const MAP_SHARED: u64 = 1 << 0;
    pub const MAP_SHARED_VALIDATE: u64 = 1 << 1;
    pub const MAP_PRIVATE: u64 = 1 << 2;
    pub const MAP_32BIT: u64 = 1 << 3;
    pub const MAP_ANONYMOUS: u64 = 1 << 4;
    pub const MAP_ANON: u64 = 1 << 4;
    pub const MAP_DENYWRITE: u64 = 1 << 5;
    pub const MAP_EXECUTABLE: u64 = 1 << 6;
    pub const MAP_FILE: u64 = 1 << 7;
    pub const MAP_FIXED: u64 = 1 << 8;
    pub const MAP_FIXED_NOREPLACE: u64 = 1 << 9;
    pub const MAP_GROWSDOWN: u64 = 1 << 10;
    pub const MAP_HUGETLB: u64 = 1 << 11;
    pub const MAP_HUGE_2MB: u64 = 1 << 12;
    pub const MAP_HUGE_1GB: u64 = 1 << 13;
    pub const MAP_LOCKED: u64 = 1 << 14;
    pub const MAP_NONBLOCK: u64 = 1 << 15;
    pub const MAP_NORESERVE: u64 = 1 << 16;
    pub const MAP_POPULATE: u64 = 1 << 17;
    pub const MAP_STACK: u64 = 1 << 18;
    pub const MAP_SYNC: u64 = 1 << 19;
    pub const MAP_UNINITIALIZED: u64 = 1 << 20;

    pub const fn new() -> Self {
        MmapFlags(0)
    }

    // creates MmapFlags with inputted flags
    pub const fn with_flags(self, flag: u64) -> Self {
        MmapFlags(self.0 | flag)
    }

    // Checks if MmapFlags contains input flags
    pub const fn contains(self, flag: u64) -> bool {
        (self.0 & flag) != 0
    }

    // returns the MmapFlags
    pub const fn bits(self) -> u64 {
        self.0
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

pub fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: i64, offset: u64) -> Option<u64> {
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
    let mut begin_addr = unsafe { (*pcb).mmap_address };
    // We must return the original beginning address while adjusting the value of MMAP_ADDR
    // for the next calls to MMAP
    let addr_to_return = begin_addr;
    let mut mmap_call = MmapCall::new(begin_addr, begin_addr + len, fd, offset);
    if begin_addr + offset > (*HHDM_OFFSET).as_u64() {
        serial_println!("Ran out of virtual memory for mmap call.");
        return Some((*HHDM_OFFSET).as_u64());
    }
    if flags == MmapFlags::MAP_ANONYMOUS {
        map_memory(&mut begin_addr, len, prot, &mut mmap_call);
    } else {
        allocate_file_memory(&mut begin_addr, len, fd, prot, offset, &mut mmap_call);
    }
    unsafe {
        (*pcb).mmaps.push(mmap_call);
    }
    unsafe {
        (*pcb).mmap_address = begin_addr;
    }
    Some(addr_to_return)
}

fn map_memory(begin_addr: &mut u64, len: u64, prot: u64, mmap_call: &mut MmapCall) {
    let pml4 = Cr3::read().0;
    let new_pml4_phys = pml4.start_address();
    let new_pml4_virt = VirtAddr::new((*HHDM_OFFSET).as_u64()) + new_pml4_phys.as_u64();
    let new_pml4_ptr: *mut PageTable = new_pml4_virt.as_mut_ptr();

    let mut mapper =
        unsafe { OffsetPageTable::new(&mut *new_pml4_ptr, VirtAddr::new((*HHDM_OFFSET).as_u64())) };

    let page_count = len / PAGE_SIZE as u64;
    for _ in 0..page_count {
        let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(*begin_addr));
        let flags = protection_to_pagetable_flags(prot);
        create_not_present_mapping(page, &mut mapper, Some(flags));
        serial_println!("MAPPING MEMORY PAGE {:?}", page);
        mmap_call.loaded.push(false);
        *begin_addr += PAGE_SIZE as u64;
    }

    mmap_call.fd = -1;
    mmap_call.offset = 0;
}

fn allocate_file_memory(
    begin_addr: &mut u64,
    len: u64,
    fd: i64,
    prot: u64,
    offset: u64,
    mmap_call: &mut MmapCall,
) {
    let page_count = len / PAGE_SIZE as u64;
    for _ in 0..page_count {
        let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(*begin_addr));
        let mut mapper = KERNEL_MAPPER.lock();
        let flags = protection_to_pagetable_flags(prot);
        create_not_present_mapping(page, &mut *mapper, Some(flags));
        *begin_addr += PAGE_SIZE as u64;
    }

    mmap_call.fd = fd;
    mmap_call.offset = offset;
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::{
            memory::PAGE_SIZE,
            processes::{MMAP_ANON_SIMPLE, SYSCALL_MMAP_MEMORY},
        },
        events::schedule_process,
        processes::process::{create_process, run_process_ring3, PCB, PROCESS_TABLE},
        serial_println,
        syscalls::mmap::MMAP_ADDR,
    };

    use super::{sys_mmap, MmapFlags, ProtFlags};

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
