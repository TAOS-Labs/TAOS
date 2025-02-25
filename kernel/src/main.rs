//! TAOS Kernel Entry Point

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![feature(naked_functions)]
#![test_runner(taos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use limine::request::{RequestsEndMarker, RequestsStartMarker};
use taos::events::{run_loop, schedule_kernel};

extern crate alloc;
use taos::{debug, serial_println};

/// Marks the start of Limine boot protocol requests.
#[used]
#[link_section = ".requests_start_marker"]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

/// Marks the end of Limine boot protocol requests.
#[used]
#[link_section = ".requests_end_marker"]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// Kernel entry point called by the bootloader.
///
/// # Safety
///
/// This function is unsafe as it:
/// - Assumes proper bootloader setup
/// - Performs direct hardware access
/// - Must never return
#[no_mangle]
extern "C" fn _start() -> ! {
    let bsp_id = taos::init::init();
    #[cfg(test)]
    test_main();

    schedule_kernel(taos::init::spawn_test(), 0);

    // let pid = create_process(PRINT_AND_SLEEP);
    // schedule_process(pid);

    // schedule_kernel(async move {
    //     serial_println!("Sleeping");
    //     let sleep = nanosleep_current_event(10_000_000_000);
    //     if sleep.is_some() {
    //         sleep.unwrap().await;
    //     }
    //     serial_println!("Woke up");
    // }, 0);

    // schedule_kernel(async move {
    //     serial_println!("Sleeping 2");
    //     let sleep = nanosleep_current_event(5_000_000_000);
    //     if sleep.is_some() {
    //         sleep.unwrap().await;
    //     }
    //     serial_println!("Woke up 2");
    // }, 0);

    // let pid2 = create_process(LONG_LOOP);
    // schedule_process(pid2);

    debug!("BSP entering event loop");

    unsafe { run_loop(bsp_id) }
}

/// Production panic handler.
#[cfg(not(test))]
#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    use taos::serial_println;
    serial_println!("Kernel panic: {}", info);
    taos::idle_loop();
}

/// Test panic handler.
#[cfg(test)]
#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    taos::test_panic_handler(info);
}
