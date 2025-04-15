//! Keyboard management
//!
//! Currently does not support fancy stuff like key repeats
use crate::{
    interrupts::{idt::without_interrupts, x2apic},
    serial_println,
};
use core::{
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use futures_util::stream::{Stream, StreamExt}; // StreamExt trait for .next() method
use pc_keyboard::{
    layouts, DecodedKey, Error, HandleControl, KeyCode, KeyState, Keyboard, Modifiers, ScancodeSet1,
};
use spin::Mutex;
use x86_64::{instructions::port::Port, structures::idt::InterruptStackFrame};

/// Maximum number of keyboard events to store in the buffer
const KEYBOARD_BUFFER_SIZE: usize = 32;

/// The global keyboard state
pub static KEYBOARD: Mutex<KeyboardState> = Mutex::new(KeyboardState::new());

/// Has the keyboard been initialized
static KEYBOARD_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// The number of keyboard interrupts received
static KEYBOARD_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Wake task waiting for keyboard input
static KEYBOARD_WAKER: Mutex<Option<Waker>> = Mutex::new(None);

/// Represents a key event with additional metadata
#[derive(Debug, Clone)]
pub struct BufferKeyEvent {
    /// The key code from the event
    pub key_code: KeyCode,
    /// The key state (up or down)
    pub state: KeyState,
    /// The decoded key if applicable
    pub decoded: Option<DecodedKey>,
}

/// Structure to track keyboard state
pub struct KeyboardState {
    /// The pc_keyboard handler
    keyboard: Keyboard<layouts::Us104Key, ScancodeSet1>,
    /// Circular buffer for key events
    buffer: [Option<BufferKeyEvent>; KEYBOARD_BUFFER_SIZE],
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
        const NONE_OPTION: Option<BufferKeyEvent> = None;
        Self {
            keyboard: Keyboard::new(
                ScancodeSet1::new(),
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

    /// Process a scancode and add resulting key events to the buffer
    pub fn process_scancode(&mut self, scancode: u8) -> Result<(), Error> {
        if let Some(key_event) = self.keyboard.add_byte(scancode)? {
            let decoded = self.keyboard.process_keyevent(key_event.clone());

            let buff_event = BufferKeyEvent {
                key_code: key_event.code,
                state: key_event.state,
                decoded,
            };

            self.push_event(buff_event);
        }

        Ok(())
    }

    /// Push an event to the buffer
    fn push_event(&mut self, event: BufferKeyEvent) {
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
    }

    /// Read a key event from the buffer
    pub fn read_event(&mut self) -> Option<BufferKeyEvent> {
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
        const NONE_OPTION: Option<BufferKeyEvent> = None;
        self.buffer = [NONE_OPTION; KEYBOARD_BUFFER_SIZE];
        self.read_pos = 0;
        self.write_pos = 0;
        self.full = false;
    }
}

/// Initialize the keyboard system
pub fn init() -> Result<(), &'static str> {
    if KEYBOARD_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    KEYBOARD_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

/// Get a stream of keyboard events
pub fn get_stream() -> KeyboardStream {
    KeyboardStream
}

/// Wait for and return the next key event
pub async fn next_key() -> BufferKeyEvent {
    KeyboardStream.next().await.unwrap()
}

/// Read a key without waiting
pub fn try_read_key() -> Option<BufferKeyEvent> {
    without_interrupts(|| KEYBOARD.lock().read_event())
}

pub extern "x86-interrupt" fn keyboard_handler(_frame: InterruptStackFrame) {
    KEYBOARD_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);

    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };

    let mut keyboard = KEYBOARD.lock();
    if let Err(e) = keyboard.process_scancode(scancode) {
        serial_println!("Error processing keyboard scancode: {:?}", e);
    }

    x2apic::send_eoi();
}

impl Stream for KeyboardStream {
    type Item = BufferKeyEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut keyboard = KEYBOARD.lock();

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
