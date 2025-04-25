//! TAOS Kernel Entry Point

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(taos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use limine::request::{RequestsEndMarker, RequestsStartMarker};
use taos::{debug, events::run_loop, shell};

extern crate alloc;

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

    debug!("BSP entering event loop");

    // unsafe { shell::init() };

    unsafe {
        run_loop(bsp_id);
    }
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
