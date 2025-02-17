//! Interrupt handling and management.
//!
//! This module provides:
//! - Interrupt Descriptor Table (IDT) setup
//! - Exception handlers (breakpoint, page fault, double fault, etc.)
//! - Timer interrupt handling
//! - Functions to enable/disable interrupts

use lazy_static::lazy_static;
use x86_64::instructions::interrupts;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::constants::idt::TIMER_VECTOR;
use crate::interrupts::x2apic;
use crate::prelude::*;

lazy_static! {
    /// The system's Interrupt Descriptor Table.
    /// Contains handlers for:
    /// - CPU exceptions (breakpoint, page fault, double fault)
    /// - Timer interrupts
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(0);
        }
        idt[TIMER_VECTOR].set_handler_fn(timer_handler);
        idt
    };
}

/// Loads the IDT for the specified CPU core.
pub fn init_idt(_cpu_id: u32) {
    IDT.load();
}

/// Enables interrupts on the current CPU.
pub fn enable() {
    interrupts::enable();
}

/// Disables interrupts on the current CPU.
pub fn disable() {
    interrupts::disable();
}

/// Executes a closure with interrupts disabled.
///
/// # Arguments
/// * `f` - The closure to execute
///
/// # Returns
/// Returns the result of the closure
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    interrupts::without_interrupts(f)
}

/// Checks if interrupts are enabled on the current CPU.
pub fn are_enabled() -> bool {
    interrupts::are_enabled()
}

/// Executes a closure with interrupts enabled, restoring the previous interrupt state after.
///
/// # Arguments
/// * `f` - The closure to execute
///
/// # Returns
/// Returns the result of the closure
pub fn with_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let initially_enabled = are_enabled();
    if !initially_enabled {
        enable();
    }

    let result = f();

    if !initially_enabled {
        disable();
    }

    result
}

/// Handles breakpoint exceptions by printing debug information.
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

/// Handles double fault exceptions by panicking with debug information.
extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

/// Handles page fault exceptions by printing fault information.
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    let faulting_address = Cr2::read();

    serial_println!(
        "EXCEPTION: PAGE FAULT\nFaulting Address: {:?}\nError Code: {:X}\n{:#?}",
        faulting_address,
        error_code,
        stack_frame
    );

    //panic!("PAGE FAULT!");
}

/// Handles timer interrupts by currently sending End of Interrupt (EOI) to the APIC.
extern "x86-interrupt" fn timer_handler(_: InterruptStackFrame) {
    x2apic::send_eoi();
}
