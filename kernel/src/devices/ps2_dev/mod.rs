//! PS/2 device management module
//!
//! This module provides interfaces for PS/2 devices including
//! keyboard and mouse through the PS/2 controller.

pub mod controller;
pub mod keyboard;
pub mod mouse;

use crate::interrupts::x2apic;

/// Initialize the PS/2 subsystem
pub fn init() {
    // Initialize controller first
    controller::init().expect("Failed to initialize controller");

    keyboard::init();
    mouse::init();
}

/// PS/2 keyboard interrupt handler
pub extern "x86-interrupt" fn keyboard_interrupt_handler(
    _frame: x86_64::structures::idt::InterruptStackFrame,
) {
    keyboard::keyboard_handler();
    x2apic::send_eoi();
}

/// PS/2 mouse interrupt handler
pub extern "x86-interrupt" fn mouse_interrupt_handler(
    _frame: x86_64::structures::idt::InterruptStackFrame,
) {
    mouse::mouse_handler();
    x2apic::send_eoi();
}
