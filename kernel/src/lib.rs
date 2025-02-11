#![feature(abi_x86_interrupt)]
#![no_std]
extern crate alloc;

use x86_64::instructions::hlt;

pub mod constants;
pub mod devices;
pub mod filesys;
pub mod interrupts;
pub mod memory;

pub mod events;

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
