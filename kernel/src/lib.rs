#![feature(abi_x86_interrupt)]
#![cfg_attr(feature = "strict", deny(warnings))]
#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use x86_64::instructions::hlt;

pub mod constants;
pub mod devices;
pub mod events;
pub mod filesys;
pub mod init;
pub mod interrupts;
pub mod logging;
pub mod memory;

pub use devices::serial;

pub mod prelude {
    pub use crate::debug_print;
    pub use crate::debug_println;
    pub use crate::serial_print;
    pub use crate::serial_println;
}

#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        $crate::serial_print!($($arg)*);
    }
}

#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        $crate::serial_println!($($arg)*);
    }
}

pub fn idle_loop() -> ! {
    loop {
        hlt();
    }
}

pub trait Testable {
    fn run(&self);
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        serial_println!("TEST: {}...\t", core::any::type_name::<T>());
        self();
        serial_println!("[ok]\n");
    }
}

#[no_mangle]
pub fn test_runner(tests: &[&dyn Testable]) {
    serial_print!("INFO: Running {} tests...\n", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu(QemuExitCode::Success);
}

pub fn test_panic_handler(info: &core::panic::PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    idle_loop();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    serial_println!("!!! RUNNING LIBRARY TESTS !!!");
    init::init();
    test_main();
    idle_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    test_panic_handler(info)
}

#[test_case]
fn trivial_lib_assertion() {
    assert_eq!(1, 1);
}
