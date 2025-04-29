extern crate alloc;

use crate::{
    constants::{
        processes::{MAX_FILES, PROCESS_NANOS, PROCESS_TIMESLICE},
        syscalls::START_MMAP_ADDRESS,
    },
    debug,
    events::{
        current_running_event, current_running_event_info, nanosleep_current_process,
        runner_timestamp, yield_now, EventInfo,
    },
    filesys::File,
    interrupts::{
        gdt,
        x2apic::{self, nanos_to_ticks},
    },
    ipc::namespace::Namespace,
    memory::{
        frame_allocator::{alloc_frame, dealloc_frame, with_buddy_frame_allocator},
        mm::Mm,
        HHDM_OFFSET, KERNEL_MAPPER,
    },
    processes::{loader::load_elf, registers::Registers},
    serial_println,
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::{
    arch::naked_asm,
    borrow::BorrowMut,
    cell::UnsafeCell,
    sync::atomic::{AtomicU32, Ordering},
};
use spin::{rwlock::RwLock, Mutex};
use x86_64::{
    instructions::interrupts,
    structures::paging::{OffsetPageTable, PageTable, PhysFrame, Size4KiB}, VirtAddr,
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
    Kernel,
}

#[derive(Debug, Clone)]
/// TODO:Put locks around all of this for supporting multithreadings
pub struct PCB {
    pub pid: u32,
    pub state: ProcessState,
    pub kernel_rsp: u64,
    pub kernel_rip: u64,
    pub reentry_arg1: u64,
    pub reentry_rip: u64,
    pub in_kernel: bool,
    pub next_preemption_time: u64,
    pub registers: Registers,
    pub mmap_address: u64,
    pub fd_table: [Option<Arc<Mutex<File>>>; MAX_FILES],
    pub next_fd: Arc<Mutex<usize>>,
    pub mm: Mm,
    pub namespace: Namespace,
    pub signal_descriptor: Arc<Mutex<SignalDescriptor>>,
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

pub fn with_current_pcb<F, R>(f: F) -> R
where
    F: FnOnce(&mut PCB) -> R,
{
    let pid = get_current_pid();
    let process_table = PROCESS_TABLE.read();
    let process = process_table
        .get(&pid)
        .expect("can't find pcb in process table")
        .clone();

    let pcb = unsafe { &mut *process.pcb.get() };
    f(pcb)
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
        reentry_arg1: 0,
        reentry_rip: 0,
        in_kernel: false,
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
        mmap_address: START_MMAP_ADDRESS,
        fd_table: [const { None }; MAX_FILES],
        // 0 and 1 are stdin, stdout
        next_fd: Arc::new(Mutex::new(2)),
        next_preemption_time: 0,
        mm,
        namespace: Namespace::new(),
        signal_descriptor: Arc::new(Mutex::new(SignalDescriptor::new(0, VirtAddr::new(0),0))),
    }));
    PROCESS_TABLE.write().insert(pid, Arc::clone(&process));
    pid
}

pub fn create_process(elf_bytes: &[u8], args: Vec<String>, envs: Vec<String>) -> u32 {
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

    let (stack_top, entry_point) = load_elf(
        elf_bytes,
        &mut mapper,
        &mut KERNEL_MAPPER.lock(),
        mm.borrow_mut(),
        args,
        envs,
    );

    let process = Arc::new(UnsafePCB::new(PCB {
        pid,
        state: ProcessState::New,
        kernel_rsp: 0,
        kernel_rip: 0,
        reentry_arg1: 0,
        reentry_rip: 0,
        in_kernel: false,
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
            rsp: stack_top.as_u64() - 16,
            rip: entry_point,
            rflags: 0x202,
        },
        mmap_address: START_MMAP_ADDRESS,
        fd_table: [const { None }; MAX_FILES],
        // 0 and 1 are stdin, stdout
        next_fd: Arc::new(Mutex::new(2)),
        mm,
        namespace: Namespace::new(),
        signal_descriptor: Arc::new(Mutex::new(SignalDescriptor::new(0, VirtAddr::new(0),0))),
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
            (*ptr)[i].set_addr(kernel_pml4[i].addr(), kernel_pml4[i].flags());
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

use super::{registers::ForkingRegisters, signals::SignalDescriptor};

/// run a process in ring 3
/// # Safety
///
/// This process is unsafe because it directly modifies registers
#[no_mangle]
pub async unsafe fn run_process_ring3(pid: u32) {
    resume_process_ring3(pid);

    loop {
        let process = {
            let process_table = PROCESS_TABLE.read();
            let Some(process) = process_table.get(&pid) else {
                serial_println!("Exiting");
                return;
            };
            process.clone()
        };

        // Do not lock lowest common denominator
        // Once kernel threads are in, will need lock around PCB
        // But not TCB
        let process = process.pcb.get();

        let arg1 = (*process).reentry_arg1;
        let reentry_rip = (*process).reentry_rip;
        let kernel_rsp = &mut (*process).kernel_rsp as *mut u64 as u64;
        let in_kernel = (*process).in_kernel;

        if (*process).state == ProcessState::Blocked || (*process).state == ProcessState::Ready {
            interrupts::disable();

            yield_now().await;
            if in_kernel {
                // Switch back to syscall stack
                unsafe {
                    asm!(
                        "push rax",
                        "push rcx",
                        "push rdx",
                        "call resume_syscall",
                        "pop rdx",
                        "pop rcx",
                        "pop rax",
                        in("rdi") arg1,
                        in("rsi") reentry_rip,
                        in("rdx") kernel_rsp as *mut u64,
                    );
                }
            } else {
                // Came from process (likely timer interrupt preemption)
                // No need to check any futures, can simply resume the process
                resume_process_ring3(arg1 as u32);
            }
        }
    }
}

#[unsafe(naked)]
#[no_mangle]
/// # Safety
/// Don't call this unless you are run_process_ring3
unsafe extern "C" fn resume_syscall(arg1: u64, reentry_rip: u64, kernel_rsp: *mut u64) {
    core::arch::naked_asm!(
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
        "swapgs",
        "mov r11, rsp",
        "mov [rdx], r11",            // Save kernel RSP to return
        "mov rsp, qword ptr gs:[4]", // Switch to syscall RSP
        "mov rdi, rdi",
        "push rsi", // Call syscall (using syscall stack)
        "cli",      // TODO is this safe???
        "ret",
    );
}

/// # Safety
/// Don't call this unless you are run_process_ring3
pub unsafe fn resume_process_ring3(pid: u32) {
    interrupts::disable();
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

    let registers: &mut Registers = &mut (*process).registers;
    
    let x = (*process).signal_descriptor.lock().handle_signal(registers);
    if x != 0 {
        serial_println!("TRIED HANDLING SIGNAL");

        serial_println!("Registers are {:#?}", registers);
    }

    (*process).kernel_rip = return_process as usize as u64;
    (*process).next_preemption_time = runner_timestamp() + nanos_to_ticks(PROCESS_TIMESLICE);

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
            in("r8")  &(*process).state,
        );
    }
}

#[unsafe(naked)]
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

#[unsafe(naked)]
#[no_mangle]
/// # Safety
/// Don't call this directly, use function pointers
pub unsafe fn return_process() {
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
        x2apic::send_eoi();
        return;
    }

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let Some(process) = process_table.get_mut(&event.pid) else {
            debug!(
                "Tried to preempt exited process...eid {}",
                current_running_event().unwrap().id()
            );
            x2apic::send_eoi();
            return;
        };

        let pcb = process.pcb.get();

        // Don't preempt if conditions are not met
        if (*pcb).state != ProcessState::Running
            || (*pcb).next_preemption_time <= runner_timestamp()
        {
            x2apic::send_eoi();
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

        (*pcb).reentry_arg1 = event.pid as u64;
        (*pcb).reentry_rip = resume_process_ring3 as usize as u64;

        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        // schedule_process(event.pid);

        // // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );

        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        // core::arch::asm!(
        //     "mov r11, rsp",   // Move RSP to R11
        //     "mov [rcx], r11", // store RSP (from R11)"
        //     "mov rsp, {0}",
        //     "push {1}",
        //     in(reg) preemption_info.0,
        //     in(reg) preemption_info.1,
        //     in("rcx") preemption_info.2,
        //     out("r11") _
        // );

        x2apic::send_eoi();

        core::arch::asm!("ret");
    }
}

pub fn sleep_process_int(nanos: u64, rsp: u64) {
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

        let stack_ptr = rsp as *const u64;

        // save registers to the PCB
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

pub fn sleep_process_syscall(nanos: u64, reg_vals: &ForkingRegisters) {
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

        (*pcb).registers.rax = 0; // nanosleep return value (when not interrupted)
        (*pcb).registers.rbx = reg_vals.rbx;
        (*pcb).registers.rcx = reg_vals.rcx;
        (*pcb).registers.rdx = reg_vals.rdx;
        (*pcb).registers.rsi = reg_vals.rsi;
        (*pcb).registers.rdi = reg_vals.rdi;
        (*pcb).registers.r8 = reg_vals.r8;
        (*pcb).registers.r9 = reg_vals.r9;
        (*pcb).registers.r10 = reg_vals.r10;
        (*pcb).registers.r11 = reg_vals.r11;
        (*pcb).registers.r12 = reg_vals.r12;
        (*pcb).registers.r13 = reg_vals.r13;
        (*pcb).registers.r14 = reg_vals.r14;
        (*pcb).registers.r15 = reg_vals.r15;
        (*pcb).registers.rbp = reg_vals.rbp;
        // saved from interrupt stack frame
        (*pcb).registers.rsp = reg_vals.rsp;
        (*pcb).registers.rip = reg_vals.rcx; // SYSCALL rcx stores RIP
        (*pcb).registers.rflags = reg_vals.r11; // SYSCALL r11 stores RFLAGS

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

        core::arch::asm!("swapgs", "ret");
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::processes::TEST_EXIT_CODE,
        memory::{mm::Mm, HHDM_OFFSET},
        processes::loader::load_elf,
    };

    use super::*;
    use core::slice;
    use x86_64::{
        structures::paging::{OffsetPageTable, PageTable, PhysFrame},
        PhysAddr,
    };

    #[test_case]
    async fn verify_stack_args_envs() {
        // ------ setup exactly as before ------
        let mut user_mapper = unsafe {
            let pml4 = create_process_page_table();
            let virt = *HHDM_OFFSET + pml4.start_address().as_u64();
            let ptr = virt.as_mut_ptr::<PageTable>();
            OffsetPageTable::new(&mut *ptr, *HHDM_OFFSET)
        };
        let args = alloc::vec!["foo".into(), "bar".into()];
        let envs = alloc::vec!["X=1".into(), "Y=two".into()];
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mut mm = Mm::new(pml4_frame);

        // call loader: `sp` is the address of the u64 slot containing `argc`
        let (sp, _entry) = load_elf(
            TEST_EXIT_CODE,
            &mut user_mapper,
            &mut KERNEL_MAPPER.lock(),
            &mut mm,
            args.clone(),
            envs.clone(),
        );

        // total u64 slots we pushed: envs + NULL, args + NULL, argc
        let nen = envs.len() as u64;
        let nar = args.len() as u64;

        // ---- 1) verify argc ----
        // `sp` points at argc, so just read it
        let got_argc = unsafe { (sp.as_u64() as *const u64).read() };
        assert_eq!(got_argc, nar, "argc mismatch");

        // 2) verify argv
        let argv0_ptr = (sp.as_u64() - 8 * (nar + 1)) as *const u64;
        (0..(nar as usize)).for_each(|i| {
            // read argv[i]
            let str_addr = unsafe { argv0_ptr.add(i).read() as *const u8 };
            // walk until NUL
            let mut len = 0;
            while unsafe { *str_addr.add(len) } != 0 {
                len += 1;
            }
            let got = core::str::from_utf8(unsafe { slice::from_raw_parts(str_addr, len) })
                .expect("Invalid UTF-8 in argv");
            serial_println!("GOT: {:#?}", got);
            assert_eq!(got, &args[i], "argv[{}] mismatch", i);
        });

        // ---- 3) verify envp pointers & strings ----
        // envp[] sits *below* argv array + its NULL terminator:
        // offset = sp - 8 * (nar + 1) - 8 * (nen + 1)
        let envp0_ptr = (
            sp.as_u64()
            - 8 * (nar + 1)       // skip argv + NULL
            - 8 * (nen + 1)
            // skip envp + NULL
        ) as *const u64;
        (0..(nen as usize)).for_each(|i| {
            let str_addr = unsafe { envp0_ptr.add(i).read() as *const u8 };
            let mut len = 0;
            while unsafe { *str_addr.add(len) } != 0 {
                len += 1;
            }
            let got = core::str::from_utf8(unsafe { slice::from_raw_parts(str_addr, len) })
                .expect("Invalid UTF-8 in envp");
            assert_eq!(got, &envs[i], "envp[{}] mismatch", i);
        });
    }
}
