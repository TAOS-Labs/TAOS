#![no_std]
#![no_main]
#![cfg_attr(feature = "strict", deny(warnings))]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, RequestsEndMarker, RequestsStartMarker,
    SmpRequest,
};
use limine::response::MemoryMapResponse;
use limine::smp::{Cpu, RequestFlags};
use limine::BaseRevision;
use taos::constants::x2apic::CPU_FREQUENCY;
use taos::events::futures::print_nums_after_rand_delay;
use taos::events::{register_event_runner, run_loop, schedule};
use taos::interrupts::{gdt, idt, x2apic};
use x86_64::VirtAddr;

extern crate alloc;
use alloc::boxed::Box;

use taos::filesys::block::memory::MemoryBlockDevice;
use taos::filesys::fat16::Fat16;
use taos::filesys::{FileSystem, SeekFrom};
use taos::{
    idle_loop,
    memory::{
        boot_frame_allocator::BootIntoFrameAllocator,
        frame_allocator::{GlobalFrameAllocator, FRAME_ALLOCATOR},
        heap, paging,
    },
    serial_println,
};

#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[link_section = ".requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".requests"]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[link_section = ".requests"]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[link_section = ".requests"]
static SMP_REQUEST: SmpRequest = SmpRequest::new().with_flags(RequestFlags::X2APIC);

#[used]
#[link_section = ".requests_start_marker"]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[link_section = ".requests_end_marker"]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

static BOOT_COMPLETE: AtomicBool = AtomicBool::new(false);
static MEMORY_SETUP: AtomicBool = AtomicBool::new(false);
static CPU_COUNT: AtomicU64 = AtomicU64::new(0);

// ASYNC
async fn test_sum(start: u64) -> u64 {
    let mut sum: u64 = start;
    const MAX: u64 = 10000000;
    for i in 0..MAX {
        sum += i;
        if i == MAX / 2 {
            serial_println!("Halfway through long event");
        }
    }
    sum
}

async fn test_event(arg1: u64) {
    let tv = test_sum(arg1).await;
    serial_println!("Long event result: {}", tv);
}

async fn test_event_two_blocks(arg1: u64) {
    let tv = test_sum(arg1).await;
    let tv2 = test_sum(arg1 * 2).await;
    serial_println!("Long events results: {} {}", tv, tv2);
}

#[no_mangle]
extern "C" fn kmain() -> ! {
    assert!(BASE_REVISION.is_supported());

    serial_println!("Booting BSP...");

    gdt::init(0);
    idt::init_idt(0);
    x2apic::init_bsp(CPU_FREQUENCY).expect("Failed to configure x2APIC");

    if let Some(framebuffer_response) = FRAMEBUFFER_REQUEST.get_response() {
        serial_println!("Found frame buffer");
        if let Some(framebuffer) = framebuffer_response.framebuffers().next() {
            for i in 0..100_u64 {
                let pixel_offset = i * framebuffer.pitch() + i * 4;
                unsafe {
                    *(framebuffer.addr().add(pixel_offset as usize) as *mut u32) = 0xFFFFFFFF;
                }
            }
        }
    }

    let smp_response = SMP_REQUEST.get_response().expect("SMP request failed");
    let cpu_count = smp_response.cpus().len() as u64;

    serial_println!("Detected {} CPU cores", cpu_count);

    let bsp_id = smp_response.bsp_lapic_id();
    for cpu in smp_response.cpus() {
        if cpu.id != bsp_id {
            cpu.goto_address.write(secondary_cpu_main);
        }
    }

    while CPU_COUNT.load(Ordering::SeqCst) < cpu_count - 1 {
        core::hint::spin_loop();
    }

    BOOT_COMPLETE.store(true, Ordering::SeqCst);
    serial_println!("All CPUs initialized");

    // set up page tables
    // get hhdm offset
    let memory_map_response: &MemoryMapResponse = MEMORY_MAP_REQUEST
        .get_response()
        .expect("Memory map request failed");
    let hhdm_response = HHDM_REQUEST.get_response().expect("HHDM request failed");

    let hhdm_offset: VirtAddr = VirtAddr::new(hhdm_response.offset());

    // create a basic frame allocator and set it globally
    unsafe {
        *FRAME_ALLOCATOR.lock() = Some(GlobalFrameAllocator::Boot(BootIntoFrameAllocator::init(
            memory_map_response,
        )));
    }

    let mut mapper = unsafe { paging::init(hhdm_offset) };

    heap::init_heap(&mut mapper).expect("heap initialization failed");

    let device = Box::new(MemoryBlockDevice::new(512, 512));

    // Format the filesystem
    let mut fs = Fat16::format(device).expect("Failed to format filesystem");

    // Test directory operations
    fs.create_dir("/test_dir")
        .expect("Failed to create directory");
    fs.create_dir("/test_dir/subdir")
        .expect("Failed to create subdirectory");

    // Create a test file
    fs.create_file("/test_dir/test.txt")
        .expect("FailedBlockDevice to create file");
    let fd = fs
        .open_file("/test_dir/test.txt")
        .expect("Failed to open file");

    // Write test data
    let test_data = b"Hello, TaOS FAT16!";
    let written = fs.write_file(fd, test_data).expect("Failed to write");
    assert_eq!(written, test_data.len(), "Write length mismatch");

    fs.seek_file(fd, SeekFrom::Start(0))
        .expect("Failed to seek to start");
    let mut read_buf = [0u8; 32];
    let read = fs.read_file(fd, &mut read_buf).expect("Failed to read");
    assert_eq!(read, test_data.len(), "Read length mismatch");
    assert_eq!(&read_buf[..read], test_data, "Read data mismatch");

    // List directory contents
    let entries = fs.read_dir("/test_dir").expect("Failed to read directory");
    assert!(!entries.is_empty(), "Directory should not be empty");
    assert_eq!(entries.len(), 2, "Directory should have exactly 2 entries"); // subdir and test.txt

    // Check file metadata
    let metadata = fs
        .metadata("/test_dir/test.txt")
        .expect("Failed to get metadata");
    assert_eq!(metadata.size, test_data.len() as u64, "File size mismatch");
    assert!(!metadata.is_dir, "Should not be a directory");

    // Test partial reads
    fs.seek_file(fd, SeekFrom::Start(7))
        .expect("Failed to seek");
    let mut partial_buf = [0u8; 4];
    let read = fs.read_file(fd, &mut partial_buf).expect("Failed to read");
    assert_eq!(read, 4, "Partial read length mismatch");
    assert_eq!(&partial_buf[..read], b"TaOS", "Partial read data mismatch");

    // // Close file and test removal
    fs.close_file(fd);

    fs.remove_file("/test_dir/test.txt")
        .expect("Failed to remove file");
    fs.remove_dir("/test_dir/subdir")
        .expect("Failed to remove subdirectory");
    fs.remove_dir("/test_dir")
        .expect("Failed to remove directory");

    // Verify root is empty
    let root_entries = fs.read_dir("/").expect("Failed to read root directory");
    assert_eq!(root_entries.len(), 0, "Root directory should be empty");

    serial_println!("FAT16 filesystem test passed!");

    MEMORY_SETUP.store(true, Ordering::SeqCst);

    register_event_runner(bsp_id);

    idt::enable();

    // ASYNC
    schedule(bsp_id, print_nums_after_rand_delay(0x1332), 3);
    schedule(bsp_id, print_nums_after_rand_delay(0x532), 2);
    schedule(bsp_id, test_event_two_blocks(400), 0);
    schedule(bsp_id, test_event(100), 3);

    // Try giving something to CPU 2 (note this is not how it'll be done for real, just a test)
    schedule(1, test_event(353), 1);

    serial_println!("BSP entering event loop");
    unsafe { run_loop(bsp_id) }
}

#[no_mangle]
unsafe extern "C" fn secondary_cpu_main(cpu: &Cpu) -> ! {
    CPU_COUNT.fetch_add(1, Ordering::SeqCst);
    gdt::init(cpu.id);
    idt::init_idt(cpu.id);
    x2apic::init_ap().expect("Failed to initialize core APIC");

    serial_println!("AP {} initialized", cpu.id);

    while !BOOT_COMPLETE.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }

    idt::enable();

    // To avoid constant page faults
    while !MEMORY_SETUP.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }

    let x: Box<i32> = Box::new(10);
    serial_println!(
        "AP {} Heap object allocated at: {:p}",
        cpu.id,
        Box::as_ref(&x) as *const i32
    );

    // ASYNC
    register_event_runner(cpu.id);

    schedule(cpu.id, test_event(200), 2);

    serial_println!("AP {} entering event loop", cpu.id);
    run_loop(cpu.id)
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("Kernel panic: {}", info);
    idle_loop();
}
