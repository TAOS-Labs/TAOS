//! PS/2 Mouse management
//!
//! This module handles mouse initialization, event processing,
//! and provides both synchronous and asynchronous interfaces for mouse events.

use crate::{
    devices::ps2_dev::controller,
    events::{futures::sync::BlockMutex, schedule_kernel},
    interrupts::idt::without_interrupts,
    serial_println,
};
use core::{
    fmt,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use futures_util::stream::{Stream, StreamExt};
use lazy_static::lazy_static;
use ps2::flags::MouseMovementFlags;
use spin::Mutex;

/// Maximum number of mouse events to store in the buffer
const MOUSE_BUFFER_SIZE: usize = 32;

lazy_static! {
    /// The global mouse state
    pub static ref MOUSE: BlockMutex<MouseState> = BlockMutex::new(MouseState::new());
}

/// The number of mouse interrupts received
static MOUSE_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Wake task waiting for mouse input
static MOUSE_WAKER: Mutex<Option<Waker>> = Mutex::new(None);

/// PS/2 mouse error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseError {
    /// PS/2 controller initialization error
    ControllerError,
    /// Mouse command error
    CommandError,
    /// Invalid packet data
    InvalidPacketData,
}

impl fmt::Display for MouseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ControllerError => write!(f, "PS/2 controller error"),
            Self::CommandError => write!(f, "Mouse command error"),
            Self::InvalidPacketData => write!(f, "Invalid mouse packet data"),
        }
    }
}

/// Button state for mouse buttons
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonState {
    /// Button is pressed
    Pressed,
    /// Button is released
    Released,
}

/// Represents a mouse event with additional metadata
#[derive(Debug, Clone)]
pub struct MouseEvent {
    /// X movement delta
    pub dx: i8,
    /// Y movement delta
    pub dy: i8,
    /// Z movement delta (scroll wheel)
    pub dz: i8,
    /// Left button state
    pub left_button: ButtonState,
    /// Right button state
    pub right_button: ButtonState,
    /// Middle button state
    pub middle_button: ButtonState,
    /// Absolute X position at time of event
    pub x: i16,
    /// Absolute Y position at time of event
    pub y: i16,
}

/// Structure to track mouse state
pub struct MouseState {
    /// Circular buffer for mouse events
    buffer: [Option<MouseEvent>; MOUSE_BUFFER_SIZE],
    /// Read position in the buffer
    read_pos: usize,
    /// Write position in the buffer
    write_pos: usize,
    /// Is the buffer full
    full: bool,
    /// Previous button states for tracking changes
    prev_left_button: ButtonState,
    prev_right_button: ButtonState,
    prev_middle_button: ButtonState,
    /// Current mouse X position
    mouse_x: i16,
    /// Current mouse Y position
    mouse_y: i16,
    /// Maximum X position (screen width - 1)
    max_x: i16,
    /// Maximum Y position (screen height - 1)
    max_y: i16,
}

/// Stream that yields mouse events
pub struct MouseStream;

impl Default for MouseState {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseState {
    /// Create a new mouse state
    pub const fn new() -> Self {
        const NONE_OPTION: Option<MouseEvent> = None;
        Self {
            buffer: [NONE_OPTION; MOUSE_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            full: false,
            prev_left_button: ButtonState::Released,
            prev_right_button: ButtonState::Released,
            prev_middle_button: ButtonState::Released,
            mouse_x: 0,
            mouse_y: 0,
            // Default to VGA text mode dimensions, can be updated with set_bounds
            max_x: 79,
            max_y: 24,
        }
    }

    /// Set the screen boundaries for mouse movement
    pub fn set_bounds(&mut self, width: i16, height: i16) {
        self.max_x = width - 1;
        self.max_y = height - 1;
        self.clamp_position();
    }

    /// Ensure mouse position stays within bounds
    fn clamp_position(&mut self) {
        if self.mouse_x < 0 {
            self.mouse_x = 0;
        } else if self.mouse_x > self.max_x {
            self.mouse_x = self.max_x;
        }

        if self.mouse_y < 0 {
            self.mouse_y = 0;
        } else if self.mouse_y > self.max_y {
            self.mouse_y = self.max_y;
        }
    }

    /// Get current mouse position
    pub fn get_position(&self) -> (i16, i16) {
        (self.mouse_x, self.mouse_y)
    }

    /// Set mouse position
    pub fn set_position(&mut self, x: i16, y: i16) {
        self.mouse_x = x;
        self.mouse_y = y;
        self.clamp_position();
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        !self.full && self.read_pos == self.write_pos
    }

    /// Process a complete mouse packet
    pub fn process_packet(
        &mut self,
        flags: MouseMovementFlags,
        dx: i16,
        dy: i16,
    ) -> Result<(), MouseError> {
        // Extract button states
        let left_button = if flags.contains(MouseMovementFlags::LEFT_BUTTON_PRESSED) {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };

        let right_button = if flags.contains(MouseMovementFlags::RIGHT_BUTTON_PRESSED) {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };

        let middle_button = if flags.contains(MouseMovementFlags::MIDDLE_BUTTON_PRESSED) {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };

        // Update absolute position
        self.mouse_x += dx;
        self.mouse_y += dy;

        // Ensure position stays within bounds
        self.clamp_position();

        // Create event only if there's actual movement or button state change
        if dx != 0
            || dy != 0
            || left_button != self.prev_left_button
            || right_button != self.prev_right_button
            || middle_button != self.prev_middle_button
        {
            let event = MouseEvent {
                dx: dx as i8,
                dy: dy as i8,
                dz: 0, // No scroll wheel support in basic PS/2 mouse
                left_button,
                right_button,
                middle_button,
                x: self.mouse_x,
                y: self.mouse_y,
            };

            self.push_event(event)?;

            // Update previous button states
            self.prev_left_button = left_button;
            self.prev_right_button = right_button;
            self.prev_middle_button = middle_button;
        }

        Ok(())
    }

    /// Push an event to the buffer
    fn push_event(&mut self, event: MouseEvent) -> Result<(), MouseError> {
        if self.full {
            self.read_pos = (self.read_pos + 1) % MOUSE_BUFFER_SIZE;
        }

        self.buffer[self.write_pos] = Some(event);
        self.write_pos = (self.write_pos + 1) % MOUSE_BUFFER_SIZE;

        if self.write_pos == self.read_pos {
            self.full = true;
        }

        without_interrupts(|| {
            let mut waker = MOUSE_WAKER.lock();
            if let Some(w) = waker.take() {
                w.wake();
            }
        });

        Ok(())
    }

    /// Read a mouse event from the buffer
    pub fn read_event(&mut self) -> Option<MouseEvent> {
        if self.is_empty() {
            return None;
        }

        let event = self.buffer[self.read_pos].clone();
        self.buffer[self.read_pos] = None;
        self.read_pos = (self.read_pos + 1) % MOUSE_BUFFER_SIZE;
        self.full = false;

        event
    }

    /// Clear mouse buffer
    pub fn clear_buffer(&mut self) {
        const NONE_OPTION: Option<MouseEvent> = None;
        self.buffer = [NONE_OPTION; MOUSE_BUFFER_SIZE];
        self.read_pos = 0;
        self.write_pos = 0;
        self.full = false;
    }
}

/// Initialize the mouse
pub fn init() {
    controller::with_controller(initialize_mouse);
}

/// Initialize and reset the mouse
fn initialize_mouse(controller: &mut ps2::Controller) {
    let mut mouse = controller.mouse();

    mouse
        .reset_and_self_test()
        .expect("Failed to self-test mouse");

    mouse.set_defaults().expect("Failed to set mouse defaults");

    mouse
        .enable_data_reporting()
        .expect("Failed to enable data reporting");
}

/// Get a stream of mouse events
pub fn get_stream() -> MouseStream {
    MouseStream
}

/// Wait for and return the next mouse event
pub async fn next_event() -> MouseEvent {
    MouseStream.next().await.unwrap()
}

/// Try to read a mouse event without waiting
pub fn try_read_event() -> Option<MouseEvent> {
    without_interrupts(|| match MOUSE.try_lock() {
        Ok(mut mouse) => mouse.read_event(),
        Err(_) => None,
    })
}

/// Get current mouse position
pub async fn get_position() -> (i16, i16) {
    without_interrupts(|| {
        let mouse = MOUSE.spin();
        mouse.get_position()
    })
}

/// Set mouse position
pub async fn set_position(x: i16, y: i16) {
    without_interrupts(|| {
        let mut mouse = MOUSE.spin();
        mouse.set_position(x, y);
    })
}

/// Set screen boundaries for mouse movement
pub async fn set_bounds(width: i16, height: i16) {
    without_interrupts(|| {
        let mut mouse = MOUSE.spin();
        mouse.set_bounds(width, height);
    })
}

/// Get mouse interrupt count
pub fn get_interrupt_count() -> u64 {
    MOUSE_INTERRUPT_COUNT.load(Ordering::SeqCst)
}

/// Mouse interrupt handler
pub fn mouse_handler() {
    MOUSE_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);

    controller::with_controller(|controller| {
        // Continue reading as long as data is available
        loop {
            let status = controller.read_status();
            if !status.contains(ps2::flags::ControllerStatusFlags::OUTPUT_FULL) {
                // No more data available
                break;
            }
            let mut mouse_dev = controller.mouse();

            match mouse_dev.read_data_packet() {
                Ok((flags, dx, dy)) => {
                    schedule_kernel(
                        async move {
                            let mut mouse = MOUSE.lock().await;
                            if let Err(e) = mouse.process_packet(flags, dx, dy) {
                                serial_println!("Error processing mouse packet: {:?}", e);
                            }
                        },
                        0,
                    );
                }
                Err(_) => {
                    // If we can't read a complete packet, break the loop
                    break;
                }
            }
        }
    });
}

impl Stream for MouseStream {
    type Item = MouseEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut mouse = match MOUSE.try_lock() {
            Ok(mouse) => mouse,
            Err(_) => {
                return Poll::Pending;
            }
        };

        if let Some(event) = mouse.read_event() {
            return Poll::Ready(Some(event));
        }

        // No event available, register waker for notification
        without_interrupts(|| {
            let mut waker = MOUSE_WAKER.lock();
            *waker = Some(cx.waker().clone());
        });

        Poll::Pending
    }
}
