//! Serial port interface for UART 16550 communication.
//! Provides thread-safe access to write formatted text to a serial port.

use crate::constants::ports::SERIAL_PORT;
use lazy_static::lazy_static;
use spin::Mutex;
use uart_16550::SerialPort;

lazy_static! {
    /// Thread-safe wrapper around the first serial port (COM1).
    /// Initializes the port on first access.
    pub static ref SERIAL1: Mutex<SerialPort> = {
        let mut serial_port = unsafe { SerialPort::new(SERIAL_PORT) };
        serial_port.init();
        Mutex::new(serial_port)
    };
}

#[doc(hidden)]
pub fn _print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    SERIAL1
        .lock()
        .write_fmt(args)
        .expect("Printing to serial failed");
}

/// Prints formatted text to the serial port.
///
/// # Examples
/// ```
/// serial_print!("Hello {}", "World");
/// ```
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

/// Prints formatted text to the serial port, followed by a newline.
///
/// # Examples
/// ```
/// serial_println!("Hello {}", "World");
/// ```
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}
