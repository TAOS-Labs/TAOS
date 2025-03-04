//! Kernel Initialization
//!
//! Handles the initialization of kernel subsystems and CPU cores.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::{
    request::SmpRequest,
    smp::{Cpu, RequestFlags},
    BaseRevision,
};

use crate::{
    constants::processes::{FORK_SIMPLE, MMAP_ANON_SIMPLE, PRINT_EXIT, TEST_64_PRINT_EXIT, TEST_64_SIMPLE_EXIT, TEST_SYSCALL_PRINT}, debug, devices, events::{register_event_runner, run_loop, schedule_process}, interrupts::{self, idt, x2apic}, logging, memory::{self}, processes::{
        self,
        process::{create_process, print_process_table, run_process_ring3, PROCESS_TABLE},
    }, serial_println, trace
};

extern crate alloc;

/// Limine base revision request
#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();

/// Symmetric Multi-Processing (SMP) request with x2APIC support
#[used]
#[link_section = ".requests"]
static SMP_REQUEST: SmpRequest = SmpRequest::new().with_flags(RequestFlags::X2APIC);

/// Flag indicating completion of boot process
/// Used to synchronize AP initialization
static BOOT_COMPLETE: AtomicBool = AtomicBool::new(false);

/// Counter tracking number of initialized CPUs
static CPU_COUNT: AtomicU64 = AtomicU64::new(0);

/// Initializes kernel subsystems for the Bootstrap Processor (BSP)
///
/// # Returns
/// * `u32` - The BSP's LAPIC ID
pub fn init() -> u32 {
    assert!(BASE_REVISION.is_supported());
    interrupts::init(0);

    memory::init(0);
    devices::init(0);
    // Should be kept after devices in case logging gets complicated
    // Right now log writes to serial, but if it were to switch to VGA, this would be important
    logging::init(0);
    processes::init(0);

    debug!("Waking cores");
    let bsp_id = wake_cores();

    idt::enable();
    // let addr = sys_mmap(
    //     0x1000,
    //     0x5000,
    //     ProtFlags::PROT_WRITE | ProtFlags::PROT_READ,
    //     MmapFlags::MAP_ANONYMOUS,
    //     -1,
    //     0,
    // );
    let parent_pid = create_process(TEST_64_PRINT_EXIT);
    schedule_process(parent_pid);

        // since no other processes are running or being created we assume that
        // the child pid is one more than the child pid
        // let process_table = PROCESS_TABLE.read();
        // unsafe {
        //     print_process_table(&PROCESS_TABLE);
        // }
        // assert!(process_table.contains_key(&child_pid), "Child process not found in table");

        // let parent_pcb = process_table.get(&parent_pid).expect("Could not get parent pcb from process table").pcb.get();
        // let child_pcb = process_table.get(&child_pid).expect("Could not get child pcb from process table").pcb.get();

        // // check that some of the fields are equivalent
        // unsafe {
        // assert_eq!((*parent_pcb).fd_table, (*child_pcb).fd_table);
        // assert_eq!((*parent_pcb).kernel_rip, (*child_pcb).kernel_rip);
        // assert_eq!((*parent_pcb).kernel_rsp, (*child_pcb).kernel_rsp);
        // assert_eq!((*parent_pcb).registers, (*child_pcb).registers);
        // }

        // // check that the pml4 frame is set correctly
        // unsafe {
        // verify_page_table_walk(&mut *parent_pcb, &mut *child_pcb);
        // }
    bsp_id
}

/// Entry point for Application Processors (APs)
///
/// # Arguments
/// * `cpu` - CPU information structure from Limine
///
/// # Safety
/// This function is unsafe because it:
/// - Is called directly by the bootloader
/// - Performs hardware initialization
/// - Must never return
#[no_mangle]
unsafe extern "C" fn secondary_cpu_main(cpu: &Cpu) -> ! {
    CPU_COUNT.fetch_add(1, Ordering::SeqCst);
    interrupts::init(cpu.id);
    memory::init(cpu.id);
    logging::init(cpu.id);
    processes::init(cpu.id);

    debug!("AP {} initialized", cpu.id);

    // Wait for all cores to complete initialization
    while !BOOT_COMPLETE.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }
    register_event_runner();
    idt::enable();

    debug!("AP {} entering event loop", cpu.id);

    run_loop(cpu.id)
}

/// Initializes secondary CPU cores
///
/// # Returns
/// * `u32` - The BSP's LAPIC ID
fn wake_cores() -> u32 {
    let smp_response = SMP_REQUEST.get_response().expect("SMP request failed");
    let cpu_count = smp_response.cpus().len() as u64;
    let bsp_id = smp_response.bsp_lapic_id();

    trace!("Detected {} CPU cores", cpu_count);

    // Set entry point for each AP
    for cpu in smp_response.cpus() {
        if cpu.id != bsp_id {
            cpu.goto_address.write(secondary_cpu_main);
        }
    }

    // Wait for all APs to initialize
    while CPU_COUNT.load(Ordering::SeqCst) < cpu_count - 1 {
        core::hint::spin_loop();
    }
    register_event_runner();

    BOOT_COMPLETE.store(true, Ordering::SeqCst);

    debug!("All CPUs initialized");
    bsp_id
}
