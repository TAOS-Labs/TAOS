//! Kernel Initialization
//!
//! Handles the initialization of kernel subsystems and CPU cores.

use bytes::Bytes;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use limine::{
    request::SmpRequest,
    smp::{Cpu, RequestFlags},
    BaseRevision,
};

use crate::{
    constants::processes::{TEST_MPROTECT_CHILD_WRITES, TEST_PRINT_EXIT},
    debug,
    devices::{self},
    events::{register_event_runner, run_loop, schedule_process, spawn, yield_now},
    filesys::{self},
    interrupts::{self, idt},
    ipc::{
        messages::Message,
        mnt_manager,
        namespace::Namespace,
        responses::Rattach,
        spsc::{Receiver, Sender},
    },
    logging,
    memory::{self},
    net::get_ip_addr,
    processes::{self, process::create_process},
    serial_println, trace,
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
    memory::init(0);
    interrupts::init(0);

    register_event_runner();
    devices::init(0);
    filesys::init(0);
    // Should be kept after devices in case logging gets complicated
    // Right now log writes to serial, but if it were to switch to VGA, this would be important
    logging::init(0);
    get_ip_addr().unwrap();
    processes::init(0);

    debug!("Waking cores");
    let bsp_id = wake_cores();

    idt::enable();

    let pid = create_process(TEST_MPROTECT_CHILD_WRITES);
    schedule_process(pid);

    let pid = create_process(TEST_MPROTECT_CHILD_WRITES);
    schedule_process(pid);

    let pid = create_process(TEST_MPROTECT_CHILD_WRITES);
    schedule_process(pid);

    let pid = create_process(TEST_MPROTECT_CHILD_WRITES);
    schedule_process(pid);

    let pid = create_process(TEST_MPROTECT_CHILD_WRITES);
    schedule_process(pid);

    let pid = create_process(TEST_MPROTECT_CHILD_WRITES);
    schedule_process(pid);
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

    BOOT_COMPLETE.store(true, Ordering::SeqCst);

    debug!("All CPUs initialized");

    bsp_id
}

static TEST_MOUNT_ID: AtomicU32 = AtomicU32::new(0);

static mut PLOCK: bool = true;

pub async fn run_server(server_rx: Receiver<Bytes>, server_tx: Sender<Bytes>) {
    serial_println!("Server starting");
    loop {
        match server_rx.try_recv() {
            Ok(msg_bytes) => match Message::parse(msg_bytes) {
                Ok((msg, tag)) => {
                    serial_println!("Server got message: {:?}", msg);
                    let response = match msg {
                        Message::Tattach(..) => {
                            Message::Rattach(Rattach::new(tag, Bytes::new()).unwrap())
                        }
                        _ => continue,
                    };

                    if let Ok(resp_bytes) = response.serialize() {
                        let _ = server_tx.send(resp_bytes).await;
                    }
                }
                Err(e) => serial_println!("(Server) Failed to parse message: {:?}", e),
            },
            Err(_) => unsafe {
                if PLOCK {
                    serial_println!("Got error");
                    PLOCK = false;
                }
            },
        }
        yield_now().await;
    }
}

pub async fn run_client(mount_id: u32) {
    serial_println!("Client starting");
    let mut ns = Namespace::new();

    match ns.add_mount("/test", mount_id as usize).await {
        Ok(()) => {
            serial_println!("Client added mount successfully");
            match ns.walk_path("/test/somefile").await {
                Ok(resolution) => {
                    serial_println!("Walk succeeded: {:?}", resolution);
                }
                Err(e) => serial_println!("Walk failed: {:?}", e),
            }
        }
        Err(e) => serial_println!("Client failed to add mount: {:?}", e),
    }
    serial_println!("Client finished");
}

pub async fn spawn_test() {
    serial_println!("Starting test");

    let (mount_id, _server_rx, _server_tx) = match mnt_manager.create_mount().await {
        Ok(mount) => mount,
        Err(e) => {
            serial_println!("Failed to create mount: {:?}", e);
            return;
        }
    };
    serial_println!("Created mount");

    TEST_MOUNT_ID.store(mount_id.0, Ordering::Release);

    // Spawn server task
    //let server_handle = spawn(0, run_server(server_rx, server_tx), 0);

    yield_now().await;

    let client_handle = spawn(0, run_client(mount_id.0), 0);

    if let Err(e) = client_handle.await {
        serial_println!("Client task failed: {:?}", e);
    }

    serial_println!("Test complete");
}
