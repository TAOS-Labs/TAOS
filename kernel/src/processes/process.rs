extern crate alloc;

use crate::{
    constants::{
        processes::{MAX_FILES, PROCESS_NANOS},
        syscalls::START_MMAP_ADDRESS,
    },
    debug,
    events::{
        current_running_event_info, nanosleep_current_process, runner_timestamp, schedule_process,
        EventInfo,
    },
    interrupts::{
        gdt,
        x2apic::{self, nanos_to_ticks},
    },
    memory::{
        frame_allocator::{
            alloc_frame, dealloc_frame, with_buddy_frame_allocator, with_generic_allocator,
        },
        mm::Mm,
        HHDM_OFFSET, KERNEL_MAPPER,
    },
    processes::{loader::load_elf, registers::Registers},
    serial_println,
    syscalls::mmap::MmapCall,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    arch::naked_asm, borrow::BorrowMut, cell::UnsafeCell, sync::atomic::{AtomicU32, Ordering}
};
use spin::rwlock::RwLock;
use x86_64::{
    instructions::interrupts,
    structures::paging::{OffsetPageTable, PageTable, PhysFrame, Size4KiB},
};

// process counter must be thread-safe
// PID 0 will ONLY be used for errors/PID not found
pub static NEXT_PID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    New,
    Ready,
    Running,
    Blocked,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct PCB {
    pub pid: u32,
    pub state: ProcessState,
    pub kernel_rsp: u64,
    pub kernel_rip: u64,
    pub next_preemption_time: u64,
    pub registers: Registers,
    pub mmaps: Vec<MmapCall>,
    pub mmap_address: u64,
    pub fd_table: [u64; MAX_FILES],
    pub mm: Mm,
}

pub struct UnsafePCB {
    pub pcb: UnsafeCell<PCB>,
}

impl UnsafePCB {
    pub fn new(pcb: PCB) -> Self {
        UnsafePCB {
            pcb: UnsafeCell::new(pcb),
        }
    }
}

unsafe impl Sync for UnsafePCB {}
type ProcessTable = Arc<RwLock<BTreeMap<u32, Arc<UnsafePCB>>>>;

// global process table must be thread-safe
lazy_static::lazy_static! {
    #[derive(Debug)]
    pub static ref PROCESS_TABLE: ProcessTable = Arc::new(RwLock::new(BTreeMap::new()));
}

impl PCB {
    /// Creates a page table mapper for temporary use during only process creation and cleanup
    /// # Safety
    /// TODO
    pub unsafe fn create_mapper(&mut self) -> OffsetPageTable<'_> {
        let virt = *HHDM_OFFSET + self.mm.pml4_frame.start_address().as_u64();
        let ptr = virt.as_mut_ptr::<PageTable>();
        OffsetPageTable::new(unsafe { &mut *ptr }, *HHDM_OFFSET)
    }
}

pub fn get_current_pid() -> u32 {
    let event: EventInfo = current_running_event_info();
    let process_table = PROCESS_TABLE.read();
    if process_table.contains_key(&event.pid) {
        event.pid
    } else {
        0
    }
}

/// # Safety
///
/// TODO
pub unsafe fn print_process_table(process_table: &PROCESS_TABLE) {
    let table = process_table.read();
    serial_println!("\nProcess Table Contents:");
    serial_println!("========================");

    if table.is_empty() {
        serial_println!("No processes found");
        return;
    }

    for (pid, pcb) in table.iter() {
        let pcb = pcb.pcb.get();
        serial_println!(
            "PID {}: State: {:?}, Registers: {:?}, SP: {:#x}, PC: {:#x}",
            pid,
            (*pcb).state,
            (*pcb).registers,
            (*pcb).registers.rsp,
            (*pcb).registers.rip
        );
    }
    serial_println!("========================");
}

pub fn create_placeholder_process() -> u32 {
    // Build a new process address space
    let pid = 0;
    let process_pml4_frame = unsafe { create_process_page_table() };
    let mm = Mm::new(process_pml4_frame);
    let process = Arc::new(UnsafePCB::new(PCB {
        pid,
        state: ProcessState::New,
        kernel_rsp: 0,
        kernel_rip: 0,
        registers: Registers {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rbp: 0,
            rsp: 0,
            rip: 0,
            rflags: 0x0,
        },
        mmaps: Vec::new(),
        mmap_address: START_MMAP_ADDRESS,
        fd_table: [0; MAX_FILES],
        next_preemption_time: 0,
        mm,
    }));
    PROCESS_TABLE.write().insert(pid, Arc::clone(&process));
    pid
}

pub fn create_process(elf_bytes: &[u8]) -> u32 {
    let pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    with_buddy_frame_allocator(|alloc| {
        alloc.print_free_frames();
    });
    // Build a new process address space
    let process_pml4_frame = unsafe { create_process_page_table() };
    let mut mm = Mm::new(process_pml4_frame);
    let mut mapper = unsafe {
        let virt = *HHDM_OFFSET + process_pml4_frame.start_address().as_u64();
        let ptr = virt.as_mut_ptr::<PageTable>();
        OffsetPageTable::new(&mut *ptr, *HHDM_OFFSET)
    };
    let (stack_top, entry_point) = load_elf(elf_bytes, &mut mapper, &mut KERNEL_MAPPER.lock(), mm.borrow_mut());

    let process = Arc::new(UnsafePCB::new(PCB {
        pid,
        state: ProcessState::New,
        kernel_rsp: 0,
        kernel_rip: 0,
        next_preemption_time: 0,
        registers: Registers {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rbp: 0,
            rsp: stack_top.as_u64(),
            rip: entry_point,
            rflags: 0x202,
        },
        mmaps: Vec::new(),
        mmap_address: START_MMAP_ADDRESS,
        fd_table: [0; MAX_FILES],
        mm,
    }));
    PROCESS_TABLE.write().insert(pid, Arc::clone(&process));
    debug!("Created process with PID: {}", pid);
    // schedule process (call from main)
    pid
}

/// # Safety
///
/// TODO
unsafe fn create_process_page_table() -> PhysFrame<Size4KiB> {
    let frame = alloc_frame().expect("Failed to allocate PML4 frame");

    let virt = *HHDM_OFFSET + frame.start_address().as_u64();
    let ptr = virt.as_mut_ptr::<PageTable>();

    // Initialize and copy kernel mappings
    let mapper = KERNEL_MAPPER.lock();
    unsafe {
        (*ptr).zero();
        let kernel_pml4 = mapper.level_4_table();
        for i in 256..512 {
            (*ptr)[i] = kernel_pml4[i].clone();
        }
    }

    frame
}

/// Clear the PML4 associated with the PCB
///
/// * `pcb`: The process PCB to clear memory for
pub fn clear_process_frames(pcb: &mut PCB) {
    let pml4_frame = pcb.mm.pml4_frame;
    let mapper = unsafe { pcb.create_mapper() };

    // Iterate over first 256 entries (user space)
    for i in 0..256 {
        let entry = &mapper.level_4_table()[i];
        if entry.is_unused() {
            continue;
        }

        let pdpt_frame = PhysFrame::containing_address(entry.addr());
        unsafe {
            free_page_table(pdpt_frame, 3, HHDM_OFFSET.as_u64());
        }
    }

    dealloc_frame(pml4_frame);
}

/// Helper function to recursively multi level page tables
///
/// * `frame`: the current page table frame iterating over
/// * `level`: the current level of the page table we're on
/// * `hhdm_offset`:
unsafe fn free_page_table(frame: PhysFrame, level: u8, hhdm_offset: u64) {
    let virt = hhdm_offset + frame.start_address().as_u64();
    let table = unsafe { &mut *(virt as *mut PageTable) };

    for entry in table.iter_mut() {
        if entry.is_unused() {
            continue;
        }

        if level > 1 {
            let child_frame = PhysFrame::containing_address(entry.addr());
            free_page_table(child_frame, level - 1, hhdm_offset);
        } else {
            // Free level one page
            let page_frame = PhysFrame::containing_address(entry.addr());
            dealloc_frame(page_frame);
        }
        entry.set_unused();
    }

    dealloc_frame(frame);
}

use core::arch::asm;
use x86_64::registers::control::{Cr3, Cr3Flags};

/// run a process in ring 3
/// # Safety
///
/// TODO
#[no_mangle]
pub async unsafe fn run_process_ring3(pid: u32) {
    interrupts::disable();

    serial_println!("Process {} is being scheduled", pid);

    let process = {
        let process_table = PROCESS_TABLE.read();
        let process = process_table
            .get(&pid)
            .expect("Could not find process from process table");
        process.clone()
    };

    // Do not lock lowest common denominator
    // Once kernel threads are in, will need lock around PCB
    // But not TCB
    let process = process.pcb.get();

    (*process).next_preemption_time = runner_timestamp() + nanos_to_ticks(PROCESS_NANOS);

    Cr3::write((*process).mm.pml4_frame, Cr3Flags::empty());

    let user_cs = gdt::GDT.1.user_code_selector.0;
    let user_ds = gdt::GDT.1.user_data_selector.0;

    let registers = &(*process).registers.clone();

    (*process).kernel_rip = return_process as usize as u64;

    // Stack layout to move into user mode
    unsafe {
        asm!(
            "push rax",
            "push rcx",
            "push rdx",
            "call call_process",
            "pop rdx",
            "pop rcx",
            "pop rax",
            in("rdi") registers as *const Registers,
            in("rsi") user_ds,
            in("rdx") user_cs,
            in("rcx") &(*process).kernel_rsp,
            in("r8")  &(*process).state
        );
    }
}

#[naked]
#[allow(undefined_naked_function_abi)]
#[no_mangle]
unsafe fn call_process(
    registers: *const Registers,
    user_ds: u16,
    user_cs: u16,
    kernel_rsp: *const u64,
    process_state: *const u8,
) {
    naked_asm!(
        //save callee-saved registers
        "
        push rbp
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rdi
        push rsi
        push rbx
        ",
        "mov r11, rsp",   // Move RSP to R11
        "mov [rcx], r11", // store RSP (from R11)
        // Needed for cross-privilege iretq
        "push rsi", //ss
        "mov rax, [rdi + 120]",
        "push rax", //userrsp
        "mov rax, [rdi + 136]",
        "push rax", //rflags
        "push rdx", //cs
        "mov rax, [rdi + 128]",
        "push rax",             //rip
        "mov byte ptr [r8], 2", //set state to ProcessState::Running
        // Restore all registers before entering process
        "mov rax, [rdi]",
        "mov rbx, [rdi+8]",
        "mov rcx, [rdi+16]",
        "mov rdx, [rdi+24]",
        "mov rsi, [rdi+32]",
        "mov r8,  [rdi+48]",
        "mov r9,  [rdi+56]",
        "mov r10, [rdi+64]",
        "mov r11, [rdi+72]",
        "mov r12, [rdi+80]",
        "mov r13, [rdi+88]",
        "mov r14, [rdi+96]",
        "mov r15, [rdi+104]",
        "mov rbp, [rdi+112]",
        "mov rdi, [rdi+40]",
        "sti",   //enable interrupts
        "iretq", // call process
    );
}

#[naked]
#[allow(undefined_naked_function_abi)]
#[no_mangle]
unsafe fn return_process() {
    naked_asm!(
        "cli", //disable interrupts
        //restore callee-saved registers
        "
        pop rbx
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
        pop rbp
        ",
        "ret", // return to event scheduler
    );
}

pub fn preempt_process(rsp: u64) {
    let event: EventInfo = current_running_event_info();
    if event.pid == 0 {
        return;
    }

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        // Don't preempt if conditions are not met
        if (*pcb).state != ProcessState::Running
            || (*pcb).next_preemption_time <= runner_timestamp()
        {
            return;
        }

        // save registers to the PCB
        let stack_ptr: *const u64 = rsp as *const u64;

        (*pcb).registers.rax = *stack_ptr.add(0);
        (*pcb).registers.rbx = *stack_ptr.add(1);
        (*pcb).registers.rcx = *stack_ptr.add(2);
        (*pcb).registers.rdx = *stack_ptr.add(3);
        (*pcb).registers.rsi = *stack_ptr.add(4);
        (*pcb).registers.rdi = *stack_ptr.add(5);
        (*pcb).registers.r8 = *stack_ptr.add(6);
        (*pcb).registers.r9 = *stack_ptr.add(7);
        (*pcb).registers.r10 = *stack_ptr.add(8);
        (*pcb).registers.r11 = *stack_ptr.add(9);
        (*pcb).registers.r12 = *stack_ptr.add(10);
        (*pcb).registers.r13 = *stack_ptr.add(11);
        (*pcb).registers.r14 = *stack_ptr.add(12);
        (*pcb).registers.r15 = *stack_ptr.add(13);
        (*pcb).registers.rbp = *stack_ptr.add(14);
        // saved from interrupt stack frame
        (*pcb).registers.rsp = *stack_ptr.add(18);
        (*pcb).registers.rip = *stack_ptr.add(15);
        (*pcb).registers.rflags = *stack_ptr.add(17);

        (*pcb).state = ProcessState::Ready;

        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        schedule_process(event.pid);

        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );

        x2apic::send_eoi();

        core::arch::asm!("ret");
    }
}

pub fn block_process(rsp: u64) {
    let event: EventInfo = current_running_event_info();
    if event.pid == 0 {
        return;
    }

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        // save registers to the PCB
        let stack_ptr: *const u64 = rsp as *const u64;

        (*pcb).registers.rax = *stack_ptr.add(0);
        (*pcb).registers.rbx = *stack_ptr.add(1);
        (*pcb).registers.rcx = *stack_ptr.add(2);
        (*pcb).registers.rdx = *stack_ptr.add(3);
        (*pcb).registers.rsi = *stack_ptr.add(4);
        (*pcb).registers.rdi = *stack_ptr.add(5);
        (*pcb).registers.r8 = *stack_ptr.add(6);
        (*pcb).registers.r9 = *stack_ptr.add(7);
        (*pcb).registers.r10 = *stack_ptr.add(8);
        (*pcb).registers.r11 = *stack_ptr.add(9);
        (*pcb).registers.r12 = *stack_ptr.add(10);
        (*pcb).registers.r13 = *stack_ptr.add(11);
        (*pcb).registers.r14 = *stack_ptr.add(12);
        (*pcb).registers.r15 = *stack_ptr.add(13);
        (*pcb).registers.rbp = *stack_ptr.add(14);
        // saved from interrupt stack frame
        (*pcb).registers.rsp = *stack_ptr.add(18);
        (*pcb).registers.rip = *stack_ptr.add(15);
        (*pcb).registers.rflags = *stack_ptr.add(17);

        (*pcb).state = ProcessState::Blocked;

        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        // TODO schedule blocked process

        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );

        x2apic::send_eoi();

        core::arch::asm!("ret");
    }
}

pub fn sleep_process(rsp: u64, nanos: u64) {
    let event: EventInfo = current_running_event_info();
    if event.pid == 0 {
        return;
    }

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        // save registers to the PCB
        let stack_ptr: *const u64 = rsp as *const u64;

        (*pcb).registers.rax = *stack_ptr.add(0);
        (*pcb).registers.rbx = *stack_ptr.add(1);
        (*pcb).registers.rcx = *stack_ptr.add(2);
        (*pcb).registers.rdx = *stack_ptr.add(3);
        (*pcb).registers.rsi = *stack_ptr.add(4);
        (*pcb).registers.rdi = *stack_ptr.add(5);
        (*pcb).registers.r8 = *stack_ptr.add(6);
        (*pcb).registers.r9 = *stack_ptr.add(7);
        (*pcb).registers.r10 = *stack_ptr.add(8);
        (*pcb).registers.r11 = *stack_ptr.add(9);
        (*pcb).registers.r12 = *stack_ptr.add(10);
        (*pcb).registers.r13 = *stack_ptr.add(11);
        (*pcb).registers.r14 = *stack_ptr.add(12);
        (*pcb).registers.r15 = *stack_ptr.add(13);
        (*pcb).registers.rbp = *stack_ptr.add(14);
        // saved from interrupt stack frame
        (*pcb).registers.rsp = *stack_ptr.add(18);
        (*pcb).registers.rip = *stack_ptr.add(15);
        (*pcb).registers.rflags = *stack_ptr.add(17);

        (*pcb).state = ProcessState::Blocked;

        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        nanosleep_current_process(event.pid, nanos);

        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );

        x2apic::send_eoi();

        core::arch::asm!("ret");
    }
}
