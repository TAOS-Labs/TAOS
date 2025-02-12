use log::{LevelFilter, Log, Metadata, Record};
use spin::Mutex;

pub static LOGGER: Logger = Logger::new();

pub struct Logger {
    inner: Mutex<()>,
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

impl Logger {
    pub const fn new() -> Logger {
        Logger {
            inner: Mutex::new(()),
        }
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // Lock the mutex before logging
            let _guard = self.inner.lock();
            crate::serial_println!("[{}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

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

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => (log::trace!($($arg)*));
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => (log::debug!($($arg)*));
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => (log::info!($($arg)*));
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => (log::warn!($($arg)*));
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => (log::error!($($arg)*));
}
