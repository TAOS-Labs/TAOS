//! Mouse management for PS/2 compatible mice
//!
//! Handles mouse initialization, event processing, and provides both
//! synchronous and asynchronous interfaces for mouse events

use crate::{
    events::schedule_kernel,
    interrupts::{idt::without_interrupts, x2apic},
    serial_println,
};
use core::{
    fmt,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use futures_util::stream::{Stream, StreamExt};
use spin::Mutex;
use x86_64::{instructions::port::Port, structures::idt::InterruptStackFrame};

/// Maximum number of mouse events to store in the buffer
const MOUSE_BUFFER_SIZE: usize = 32;

/// The global mouse state
pub static MOUSE: Mutex<MouseState> = Mutex::new(MouseState::new());

/// Has the mouse been initialized
static MOUSE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// The number of mouse interrupts received
static MOUSE_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Wake task waiting for mouse input
static MOUSE_WAKER: Mutex<Option<Waker>> = Mutex::new(None);

/// PS/2 mouse error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseError {
    /// PS/2 controller initialization error
    ControllerInitError,
    /// Timeout waiting for PS/2 controller to be ready
    ControllerTimeout,
    /// Mouse failed to acknowledge a command
    CommandAckFailed,
    /// Invalid packet data
    InvalidPacketData,
    /// Buffer overflow
    BufferOverflow,
    /// Mouse already initialized
    AlreadyInitialized,
}

/// Result type for mouse operations
pub type MouseResult<T> = core::result::Result<T, MouseError>;

impl fmt::Display for MouseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ControllerInitError => write!(f, "PS/2 controller initialization error"),
            Self::ControllerTimeout => write!(f, "Timeout waiting for PS/2 controller"),
            Self::CommandAckFailed => write!(f, "Mouse did not acknowledge command"),
            Self::InvalidPacketData => write!(f, "Invalid mouse packet data"),
            Self::BufferOverflow => write!(f, "Mouse event buffer overflow"),
            Self::AlreadyInitialized => write!(f, "Mouse already initialized"),
        }
    }
}

/// PS/2 mouse packet structure
struct MousePacket {
    flags: u8,
    x_movement: i8,
    y_movement: i8,
    z_movement: i8, // Scroll wheel
}

/// Button state for mouse buttons
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonState {
    /// Button is pressed
    Pressed,
    /// Button is released
    Released,
}

/// Mouse button identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    /// Left mouse button
    Left,
    /// Right mouse button
    Right,
    /// Middle mouse button (scroll wheel click)
    Middle,
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
#[derive(Debug)]
pub struct MouseState {
    /// Circular buffer for mouse events
    buffer: [Option<MouseEvent>; MOUSE_BUFFER_SIZE],
    /// Read position in the buffer
    read_pos: usize,
    /// Write position in the buffer
    write_pos: usize,
    /// Is the buffer full
    full: bool,
    /// Current packet being assembled
    packet_bytes: [u8; 4],
    /// Current position in the packet
    packet_index: usize,
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
            packet_bytes: [0; 4],
            packet_index: 0,
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

    /// Process a mouse data byte
    pub fn process_mouse_byte(&mut self, data: u8) -> MouseResult<()> {
        self.packet_bytes[self.packet_index] = data;
        self.packet_index += 1;

        // Standard PS/2 mouse packets are 3 bytes
        // With scroll wheel, we need 4 bytes
        if self.packet_index >= 3 {
            let packet = MousePacket {
                flags: self.packet_bytes[0],
                x_movement: self.packet_bytes[1] as i8,
                y_movement: self.packet_bytes[2] as i8,
                z_movement: if self.packet_index >= 4 {
                    self.packet_bytes[3] as i8
                } else {
                    0
                },
            };

            self.process_packet(packet)?;
            self.packet_index = 0;
        }

        Ok(())
    }

    /// Process a complete mouse packet and create an event
    fn process_packet(&mut self, packet: MousePacket) -> MouseResult<()> {
        // Extract button states
        let left_button = if packet.flags & 0x01 != 0 {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };

        let right_button = if packet.flags & 0x02 != 0 {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };

        let middle_button = if packet.flags & 0x04 != 0 {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };

        // Handle movement
        let mut dx = packet.x_movement;
        let mut dy = packet.y_movement;

        // PS/2 mouse protocol: Overflow bits
        if packet.flags & 0x40 != 0 {
            // X overflow
            dx = if dx > 0 { 127 } else { -128 };
        }
        if packet.flags & 0x80 != 0 {
            // Y overflow
            dy = if dy > 0 { 127 } else { -128 };
        }

        // PS/2 Y-axis is inverted
        dy = if dy == -128 { 127 } else { -dy };

        // Update absolute position
        let new_x = self.mouse_x + dx as i16;
        let new_y = self.mouse_y + dy as i16;

        self.mouse_x = new_x;
        self.mouse_y = new_y;

        // Ensure position stays within bounds
        self.clamp_position();

        // Create event only if there's actual movement or button state change
        if dx != 0
            || dy != 0
            || packet.z_movement != 0
            || left_button != self.prev_left_button
            || right_button != self.prev_right_button
            || middle_button != self.prev_middle_button
        {
            // Create event
            let event = MouseEvent {
                dx,
                dy,
                dz: packet.z_movement,
                left_button,
                right_button,
                middle_button,
                x: self.mouse_x,
                y: self.mouse_y,
            };

            if self.push_event(event).is_err() {
                // Buffer overflow, but we can continue processing
                serial_println!("Warning: Mouse event buffer overflow");
            }

            // Update previous button states
            self.prev_left_button = left_button;
            self.prev_right_button = right_button;
            self.prev_middle_button = middle_button;
        }

        Ok(())
    }

    /// Push an event to the buffer
    fn push_event(&mut self, event: MouseEvent) -> MouseResult<()> {
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

/// PS/2 mouse commands
#[repr(u8)]
#[allow(dead_code)]
enum PS2Command {
    /// Reset the mouse
    Reset = 0xFF,
    /// Set defaults
    SetDefaults = 0xF6,
    /// Disable data reporting
    DisableReporting = 0xF5,
    /// Enable data reporting
    EnableReporting = 0xF4,
    /// Set sample rate
    SetSampleRate = 0xF3,
    /// Get device ID
    GetDeviceId = 0xF2,
    /// Set resolution
    SetResolution = 0xE8,
    /// Status request
    StatusRequest = 0xE9,
}

/// PS/2 controller commands
#[repr(u8)]
#[allow(dead_code)]
enum PS2ControllerCommand {
    /// Read controller configuration byte
    ReadConfig = 0x20,
    /// Write controller configuration byte
    WriteConfig = 0x60,
    /// Disable second PS/2 port
    DisablePort2 = 0xA7,
    /// Enable second PS/2 port
    EnablePort2 = 0xA8,
    /// Test second PS/2 port
    TestPort2 = 0xA9,
    /// Test PS/2 controller
    TestController = 0xAA,
    /// Test first PS/2 port
    TestPort1 = 0xAB,
    /// Disable first PS/2 port
    DisablePort1 = 0xAD,
    /// Enable first PS/2 port
    EnablePort1 = 0xAE,
    /// Write to second PS/2 port
    WritePort2 = 0xD4,
}

/// PS/2 port addresses
struct PS2Port;

impl PS2Port {
    /// Data port (read/write)
    const DATA: u16 = 0x60;
    /// Status register (read), command register (write)
    const CMD_STATUS: u16 = 0x64;
}

/// PS/2 controller response bytes
struct PS2Response;

#[allow(dead_code)]
impl PS2Response {
    /// Command acknowledgement
    const ACK: u8 = 0xFA;
    /// Command not recognized
    const RESEND: u8 = 0xFE;
    /// Self-test passed
    const TEST_PASSED: u8 = 0xAA;
}

/// Initialize the mouse
pub fn init() -> MouseResult<()> {
    if MOUSE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(MouseError::AlreadyInitialized);
    }

    wait_write_ready()?;

    let mut command_port = Port::new(PS2Port::CMD_STATUS);
    unsafe {
        command_port.write(PS2ControllerCommand::WritePort2 as u8);
    }

    wait_write_ready()?;

    // Tell the mouse to enable data reporting
    let mut data_port = Port::new(PS2Port::DATA);
    unsafe {
        data_port.write(PS2Command::EnableReporting as u8);
    }

    wait_read_ready()?;
    let response: u8 = unsafe { data_port.read() };

    if response != PS2Response::ACK {
        return Err(MouseError::CommandAckFailed);
    }

    MOUSE_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

/// Wait for the PS/2 controller to be ready for reading
fn wait_read_ready() -> MouseResult<()> {
    let mut status_port = Port::new(PS2Port::CMD_STATUS);

    for _ in 0..1000 {
        let status: u8 = unsafe { status_port.read() };
        if status & 0x01 != 0 {
            return Ok(());
        }
    }

    Err(MouseError::ControllerTimeout)
}

/// Wait for the PS/2 controller to be ready for writing
fn wait_write_ready() -> MouseResult<()> {
    let mut status_port = Port::<u8>::new(PS2Port::CMD_STATUS);

    for _ in 0..1000 {
        let status: u8 = unsafe { status_port.read() };
        if status & 0x02 == 0 {
            return Ok(());
        }
    }

    Err(MouseError::ControllerTimeout)
}

/// Send a command to the PS/2 mouse
fn mouse_send_command(command: PS2Command) -> MouseResult<u8> {
    wait_write_ready()?;

    let mut command_port = Port::new(PS2Port::CMD_STATUS);
    unsafe {
        command_port.write(PS2ControllerCommand::WritePort2 as u8);
    }

    wait_write_ready()?;

    let mut data_port = Port::new(PS2Port::DATA);
    unsafe {
        data_port.write(command as u8);
    }

    wait_read_ready()?;
    let response: u8 = unsafe { data_port.read() };

    Ok(response)
}

/// Get a stream of mouse events
pub fn get_stream() -> MouseStream {
    MouseStream
}

/// Wait for and return the next mouse event
pub async fn next_event() -> MouseEvent {
    MouseStream.next().await.unwrap()
}

/// Read a mouse event without waiting
pub fn try_read_event() -> Option<MouseEvent> {
    without_interrupts(|| MOUSE.lock().read_event())
}

/// Get current mouse position
pub fn get_position() -> (i16, i16) {
    without_interrupts(|| {
        let mouse = MOUSE.lock();
        mouse.get_position()
    })
}

/// Set mouse position
pub fn set_position(x: i16, y: i16) {
    without_interrupts(|| {
        let mut mouse = MOUSE.lock();
        mouse.set_position(x, y);
    })
}

/// Set screen boundaries for mouse movement
pub fn set_bounds(width: i16, height: i16) {
    without_interrupts(|| {
        let mut mouse = MOUSE.lock();
        mouse.set_bounds(width, height);
    })
}

/// Reset the mouse to default settings
pub fn reset() -> MouseResult<()> {
    if !MOUSE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(MouseError::ControllerInitError);
    }

    let response = mouse_send_command(PS2Command::Reset)?;
    if response != PS2Response::ACK {
        return Err(MouseError::CommandAckFailed);
    }

    without_interrupts(|| {
        let mut mouse = MOUSE.lock();
        mouse.clear_buffer();
        mouse.set_position(0, 0);
    });

    Ok(())
}

/// Get mouse interrupt count
pub fn get_interrupt_count() -> u64 {
    MOUSE_INTERRUPT_COUNT.load(Ordering::SeqCst)
}

/// Mouse interrupt handler
pub extern "x86-interrupt" fn mouse_handler(_frame: InterruptStackFrame) {
    MOUSE_INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);

    let mut data_port = Port::new(PS2Port::DATA);
    let data: u8 = unsafe { data_port.read() };

    schedule_kernel(
        async move {
            let mut mouse = MOUSE.lock();
            if let Err(e) = mouse.process_mouse_byte(data) {
                serial_println!("Error processing mouse data: {:?}", e);
            }
        },
        0,
    );

    x2apic::send_eoi();
}

impl Stream for MouseStream {
    type Item = MouseEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut mouse = MOUSE.lock();

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
