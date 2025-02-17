//! Kernel logging facility
//!
//! Provides thread-safe logging functionality for the kernel using the `log` crate.
//! Log levels are configured based on build configuration (debug/release).

use log::{LevelFilter, Log, Metadata, Record};
use spin::Mutex;

/// Global logger instance available throughout the kernel
pub static LOGGER: Logger = Logger::new();

/// Thread-safe logger implementation
pub struct Logger {
    inner: Mutex<()>,
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

impl Logger {
    /// Creates a new logger instance
    pub const fn new() -> Logger {
        Logger {
            inner: Mutex::new(()),
        }
    }
}

impl Log for Logger {
    /// Determines if a log message should be processed based on its level
    ///
    /// Returns true if the message level is less than or equal to the maximum configured level
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    /// Processes and outputs a log record
    ///
    /// Formats messages as "[LEVEL] message"
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let _guard = self.inner.lock();
            crate::serial_println!("[{}] {}", record.level(), record.args());
        }
    }

    /// Flush buffered logs (no-op in this implementation)
    fn flush(&self) {}
}

/// Initializes the logging system
///
/// # Arguments
/// * `cpu_id` - CPU core identifier. Only core 0 will initialize the logger
///
/// # Notes
/// * Sets different log levels for debug/release builds:
///   - Debug builds: LevelFilter::Debug
///   - Release builds: LevelFilter::Info
pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        log::set_logger(&LOGGER)
            .map(|()| {
                log::set_max_level(
                    #[cfg(debug_assertions)]
                    LevelFilter::Debug,
                    #[cfg(not(debug_assertions))]
                    LevelFilter::Info,
                )
            })
            .expect("Logger initialization failed");
    }
}

/// Convenience macro for trace-level logging
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => (log::trace!($($arg)*));
}

/// Convenience macro for debug-level logging
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => (log::debug!($($arg)*));
}

/// Convenience macro for info-level logging
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => (log::info!($($arg)*));
}

/// Convenience macro for warning-level logging
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => (log::warn!($($arg)*));
}

/// Convenience macro for error-level logging
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => (log::error!($($arg)*));
}
