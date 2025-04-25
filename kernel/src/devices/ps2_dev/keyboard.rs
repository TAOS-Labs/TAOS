//! PS/2 Keyboard management
//!
//! This module handles keyboard initialization, event processing,
//! and provides both synchronous and asynchronous interfaces for keyboard events.

use crate::{
    devices::ps2_dev::controller,
    events::{futures::sync::BlockMutex, schedule_kernel, yield_now},
    interrupts::idt::without_interrupts,
    serial_println,
};
use core::{
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use futures_util::stream::{Stream, StreamExt};
use lazy_static::lazy_static;
use pc_keyboard::{
    layouts, DecodedKey, Error, HandleControl, KeyCode, KeyState, Keyboard, Modifiers, ScancodeSet2,
};
use ps2::flags::ControllerStatusFlags;
use spin::Mutex;

/// Maximum number of keyboard events to store in the buffer
const KEYBOARD_BUFFER_SIZE: usize = 32;

lazy_static! {
    /// The global keyboard state
    pub static ref KEYBOARD: BlockMutex<KeyboardState> = BlockMutex::new(KeyboardState::new());
}

/// The number of keyboard interrupts received
static KEYBOARD_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Wake task waiting for keyboard input
static KEYBOARD_WAKER: Mutex<Option<Waker>> = Mutex::new(None);

/// Keyboard error types
#[derive(Debug, Clone, Copy)]
pub enum KeyboardError {
    /// PS/2 controller initialization error
    ControllerError,
    /// Keyboard command error
    CommandError,
    /// Invalid scancode
    InvalidScancode,
    /// PC Keyboard error
    PCKeyboardError(Error),
}

impl From<Error> for KeyboardError {
    fn from(error: Error) -> Self {
        KeyboardError::PCKeyboardError(error)
    }
}

/// Represents a key event with additional metadata
#[derive(Debug, Clone)]
pub struct KeyboardEvent {
    /// The key code from the event
    pub key_code: KeyCode,
    /// The key state (up or down)
    pub state: KeyState,
    /// The decoded key if applicable
    pub decoded: Option<DecodedKey>,
    /// The raw scancode
    pub scancode: u8,
}

/// Keyboard state structure
pub struct KeyboardState {
    /// The pc_keyboard handler
    keyboard: Keyboard<layouts::Us104Key, ScancodeSet2>,
    /// Circular buffer for keyboard events
    buffer: [Option<KeyboardEvent>; KEYBOARD_BUFFER_SIZE],
    /// Read position in the buffer
    read_pos: usize,
    /// Write position in the buffer
    write_pos: usize,
    /// Is the buffer full
    full: bool,
}

/// Stream that yields keyboard events
pub struct KeyboardStream;

impl Default for KeyboardState {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyboardState {
    /// Create a new keyboard state
    pub const fn new() -> Self {
        const NONE_OPTION: Option<KeyboardEvent> = None;
        Self {
            keyboard: Keyboard::new(
                ScancodeSet2::new(),
                layouts::Us104Key,
                HandleControl::Ignore,
            ),
            buffer: [NONE_OPTION; KEYBOARD_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            full: false,
        }
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        !self.full && self.read_pos == self.write_pos
    }

    /// Process a scancode
    pub fn process_scancode(&mut self, scancode: u8) -> Result<(), KeyboardError> {
        if let Some(key_event) = self.keyboard.add_byte(scancode)? {
            let decoded = self.keyboard.process_keyevent(key_event.clone());

            let event = KeyboardEvent {
                key_code: key_event.code,
                state: key_event.state,
                decoded,
                scancode,
            };

            self.push_event(event)?;
        }

        Ok(())
    }

    /// Push an event to the buffer
    fn push_event(&mut self, event: KeyboardEvent) -> Result<(), KeyboardError> {
        if self.full {
            self.read_pos = (self.read_pos + 1) % KEYBOARD_BUFFER_SIZE;
        }

        self.buffer[self.write_pos] = Some(event);
        self.write_pos = (self.write_pos + 1) % KEYBOARD_BUFFER_SIZE;

        if self.write_pos == self.read_pos {
            self.full = true;
        }

        without_interrupts(|| {
            let mut waker = KEYBOARD_WAKER.lock();
            if let Some(w) = waker.take() {
                w.wake();
            }
        });

        Ok(())
    }

    /// Read a keyboard event from the buffer
    pub fn read_event(&mut self) -> Option<KeyboardEvent> {
        if self.is_empty() {
            return None;
        }

        let event = self.buffer[self.read_pos].clone();
        self.buffer[self.read_pos] = None;
        self.read_pos = (self.read_pos + 1) % KEYBOARD_BUFFER_SIZE;
        self.full = false;

        event
    }

    /// Get current modifier state
    pub fn modifiers(&self) -> &Modifiers {
        self.keyboard.get_modifiers()
    }

    /// Clear keyboard buffer
    pub fn clear_buffer(&mut self) {
        const NONE_OPTION: Option<KeyboardEvent> = None;
        self.buffer = [NONE_OPTION; KEYBOARD_BUFFER_SIZE];
        self.read_pos = 0;
        self.write_pos = 0;
        self.full = false;
    }
}

/// Initialize the keyboard
pub fn init() {
    controller::with_controller(initialize_keyboard);
}

/// Initialize and reset the keyboard
fn initialize_keyboard(controller: &mut ps2::Controller) {
    let mut keyboard = controller.keyboard();

    keyboard
        .reset_and_self_test()
        .expect("Failed keyboard reset test");

    keyboard
        .enable_scanning()
        .expect("Failed to enable scanning for keyboard");
}

/// Get a stream of keyboard events
pub fn get_stream() -> KeyboardStream {
    KeyboardStream
}

/// Wait for and return the next keyboard event
pub async fn next_event() -> KeyboardEvent {
    KeyboardStream.next().await.unwrap()
}

/// Try to read a keyboard event without waiting
pub async fn try_read_event() -> Option<KeyboardEvent> {
    without_interrupts(|| match KEYBOARD.try_lock() {
        Ok(mut keyboard) => keyboard.read_event(),
        Err(_) => None,
    })
}

/// Get keyboard interrupt count
pub fn get_interrupt_count() -> u64 {
    KEYBOARD_INTERRUPT_COUNT.load(Ordering::SeqCst)
}

/// Keyboard interrupt handler
pub fn keyboard_handler() {
    KEYBOARD_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);

    controller::with_controller(|controller| {
        // Read from the controller as long as the OUTPUT_FULL bit is set
        loop {
            let status = controller.read_status();
            if !status.contains(ps2::flags::ControllerStatusFlags::OUTPUT_FULL) {
                // No more data available
                break;
            }

            match controller.read_data() {
                Ok(scancode) => {
                    schedule_kernel(
                        async move {
                            let mut keyboard = KEYBOARD.lock().await;
                            if let Err(e) = keyboard.process_scancode(scancode) {
                                serial_println!("Error processing keyboard scancode: {:?}", e);
                            }
                        },
                        0,
                    );
                }
                Err(_) => {
                    // If we can't read data despite OUTPUT_FULL being set
                    serial_println!("Keyboard: Full bit set but got error while reading");
                    break;
                }
            }
        }
    });
}

pub async fn flush_buffer() {
    loop {
        if let Ok(mut kb) = KEYBOARD.try_lock() {
            // got the lock, clear it
            kb.clear_buffer();
            controller::with_controller(|ctrl| {
                while ctrl
                    .read_status()
                    .contains(ControllerStatusFlags::OUTPUT_FULL)
                {
                    let _ = ctrl.read_data();
                }
            });
            return;
        }
        yield_now().await;
    }
}

impl Stream for KeyboardStream {
    type Item = KeyboardEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut keyboard = match KEYBOARD.try_lock() {
            Ok(keyboard) => keyboard,
            Err(_) => {
                return Poll::Pending;
            }
        };

        if let Some(event) = keyboard.read_event() {
            return Poll::Ready(Some(event));
        }

        // No event available, register waker for notification
        without_interrupts(|| {
            let mut waker = KEYBOARD_WAKER.lock();
            *waker = Some(cx.waker().clone());
        });

        Poll::Pending
    }
}
