//! PS/2 Keyboard management
//!
//! This module handles keyboard initialization, event processing,
//! and provides both synchronous and asynchronous interfaces for keyboard events.

use crate::{
    devices::ps2_dev::controller,
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
use spin::Mutex;

/// Maximum number of keyboard events to store in the buffer
const KEYBOARD_BUFFER_SIZE: usize = 32;

lazy_static! {
    /// The global keyboard state
    pub static ref KEYBOARD: spin::Mutex<KeyboardState> = spin::Mutex::new(KeyboardState::new());
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

        // Wake the waiting reader. The waker is cloned, not taken: if
        // this wake is dropped (wake_by_ref uses try_write and may skip
        // under contention), the next scancode's wake retries instead of
        // stranding the reader asleep forever.
        let waker = without_interrupts(|| KEYBOARD_WAKER.lock().clone());
        if let Some(w) = waker {
            w.wake();
        }

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
        Some(mut keyboard) => keyboard.read_event(),
        None => None,
    })
}

/// Get keyboard interrupt count
pub fn get_interrupt_count() -> u64 {
    KEYBOARD_INTERRUPT_COUNT.load(Ordering::SeqCst)
}

/// Keyboard interrupt handler
pub fn keyboard_handler() {
    KEYBOARD_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);

    // Use try_with_controller, not with_controller: the latter blocks on a
    // spinlock, and if the IRQ fires while non-interrupt code holds it, the
    // handler would spin forever with interrupts disabled (deadlock).
    // If the lock is held, we skip this IRQ; the scancode stays in the
    // controller's output buffer and the level-triggered IRQ will re-fire.
    controller::try_with_controller(|controller| {
        // Read from the controller as long as the OUTPUT_FULL bit is set.
        // Process scancodes directly here (no async task per scancode):
        // the decode is just table lookups with no heap allocation, and
        // scheduling a task per byte was too slow — the 1-byte PS/2 output
        // buffer would overrun and drop keys under rapid input.
        // Interrupts are already disabled in handler context, so taking the
        // spinlock here cannot deadlock.
        loop {
            let status = controller.read_status();
            if !status.contains(ps2::flags::ControllerStatusFlags::OUTPUT_FULL) {
                // No more data available
                break;
            }

            match controller.read_data() {
                Ok(scancode) => {
                    // Spin (bounded) for the keyboard lock instead of dropping
                    // the scancode: every holder only takes it for a tiny,
                    // non-blocking critical section (read_event /
                    // process_scancode), so waiting briefly cannot deadlock.
                    // Dropping here lost keys under rapid input, when the
                    // shell task's poll loop contends on the lock.
                    let mut spins = 0u32;
                    let locked = loop {
                        match KEYBOARD.try_lock() {
                            Some(k) => break Some(k),
                            None => {
                                core::hint::spin_loop();
                                spins += 1;
                                if spins >= 100_000 {
                                    break None;
                                }
                            }
                        }
                    };
                    match locked {
                        Some(mut keyboard) => {
                            if let Err(e) = keyboard.process_scancode(scancode) {
                                serial_println!(
                                    "Error processing keyboard scancode: {:?}",
                                    e
                                );
                            }
                        }
                        None => {
                            serial_println!(
                                "keyboard: dropped scancode {:02x} (lock contention)",
                                scancode
                            );
                        }
                    }
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
pub fn flush_buffer() {
    without_interrupts(|| {
        if let Some(mut state) = KEYBOARD.try_lock() {
            state.clear_buffer();
        }
    })
    // controller::with_controller(|ctrl| {
    //     while ctrl
    //         .read_status()
    //         .contains(ControllerStatusFlags::OUTPUT_FULL)
    //     {
    //         let _ = ctrl.read_data(); // Discard any pending scancodes
    //     }
    // });
}

impl Stream for KeyboardStream {
    type Item = KeyboardEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<KeyboardEvent>> {
        // Register the waker, check the buffer, and go to sleep as one
        // atomic step (interrupts disabled): no IRQ can slip an event in
        // between the check and blocking, so no wake is ever missed.
        // If the buffer is empty, mark this task blocked so the executor
        // does not busy-poll it; the next IRQ's wake unblocks it.
        // Taking KEYBOARD's lock here is safe: IRQs are disabled on this
        // CPU, and any other CPU only holds it for a tiny non-blocking
        // section, so at most we spin briefly.
        without_interrupts(|| {
            *KEYBOARD_WAKER.lock() = Some(cx.waker().clone());

            let mut keyboard = KEYBOARD.lock();
            if let Some(event) = keyboard.read_event() {
                crate::events::unblock_current_event();
                Poll::Ready(Some(event))
            } else {
                crate::events::block_current_event();
                Poll::Pending
            }
        })
    }
}
