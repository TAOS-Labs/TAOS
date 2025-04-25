#![feature(naked_functions_rustic_abi)]
#![feature(abi_x86_interrupt)]
#![feature(btree_cursors)]
#![cfg_attr(feature = "strict", deny(warnings))]
#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]
#![feature(unsafe_cell_access)]

//! The TAOS operating system
extern crate alloc;

use alloc::boxed::Box;
use core::{future::Future, pin::Pin};
use events::schedule_kernel;
use x86_64::instructions::hlt;

pub mod constants;
pub mod devices;
pub mod events;
pub mod filesys;
pub mod init;
pub mod interrupts;
pub mod ipc;
pub mod logging;
pub mod memory;
pub mod net;
pub mod processes;
pub mod syscalls;

pub use devices::serial;

pub mod prelude {
    pub use crate::{debug_print, debug_println, serial_print, serial_println};
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

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub trait Testable: Sync {
    fn run(&self) -> BoxFuture<()>;
    fn name(&self) -> &str;
}

impl<F, Fut> Testable for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn run(&self) -> BoxFuture<()> {
        Box::pin(self())
    }

    fn name(&self) -> &str {
        core::any::type_name::<F>()
    }
}

pub fn test_runner(tests: &[&(dyn Testable + Send + Sync)]) {
    serial_println!("Running {} tests\n", tests.len());

    let test_futures: alloc::vec::Vec<_> = tests
        .iter()
        .map(|test| {
            let name = alloc::string::String::from(test.name());
            (name, test.run())
        })
        .collect();

    let future = async move {
        for (name, fut) in test_futures {
            serial_print!("test {}: ", name);
            fut.await;
            serial_println!("ok");
        }
        serial_println!("\ntest result: ok.");
        exit_qemu(QemuExitCode::Success);
    };

    schedule_kernel(future, 1);
}

pub fn test_panic_handler(info: &core::panic::PanicInfo) -> ! {
    serial_println!("FAILED");
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
    #[cfg(test)]
    use events::run_loop;

    serial_println!("!!! RUNNING LIBRARY TESTS !!!");
    init::init();
    test_main();
    unsafe {
        run_loop(0);
    };
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    test_panic_handler(info)
}
