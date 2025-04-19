//! PS/2 Controller management
//!
//! This module handles the low-level interaction with the PS/2 controller
//! using the ps2 crate to interface with the hardware.

use crate::serial_println;
use core::sync::atomic::{AtomicBool, Ordering};
use ps2::{error::ControllerError, flags::ControllerConfigFlags, Controller};
use spin::Mutex;

/// The global PS/2 controller
static PS2_CONTROLLER: Mutex<Option<Controller>> = Mutex::new(None);

/// Has the controller been initialized
static CONTROLLER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the PS/2 controller
pub fn init() -> Result<(), &'static str> {
    if CONTROLLER_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    // Create a new controller instance and configure it
    match initialize_controller() {
        Ok(controller) => {
            let mut controller_lock = PS2_CONTROLLER.lock();
            *controller_lock = Some(controller);
            CONTROLLER_INITIALIZED.store(true, Ordering::SeqCst);
            Ok(())
        }
        Err(e) => {
            serial_println!("PS/2 controller initialization failed: {:?}", e);
            Err("PS/2 controller initialization failed")
        }
    }
}

/// Initialize and configure the PS/2 controller
fn initialize_controller() -> Result<Controller, ControllerError> {
    // Create a new controller instance
    let mut controller = unsafe { Controller::new() };

    // Step 1: Disable devices during configuration
    controller.disable_keyboard()?;
    controller.disable_mouse()?;

    // Step 2: Flush any pending data
    let _ = controller.read_data();

    // Step 3: Set controller configuration
    let mut config = controller.read_config()?;

    // Disable interrupts and scancode translation during setup
    config.set(
        ControllerConfigFlags::ENABLE_KEYBOARD_INTERRUPT
            | ControllerConfigFlags::ENABLE_MOUSE_INTERRUPT
            | ControllerConfigFlags::ENABLE_TRANSLATE,
        false,
    );

    controller.write_config(config)?;

    // Step 4: Perform controller self-test
    controller.test_controller()?;

    // Step 5: Test PS/2 ports
    let keyboard_works = controller.test_keyboard().is_ok();
    let mouse_works = controller.test_mouse().is_ok();

    // Step 6: Enable devices
    config = controller.read_config()?;

    if keyboard_works {
        controller.enable_keyboard()?;
        config.set(ControllerConfigFlags::DISABLE_KEYBOARD, false);
        config.set(ControllerConfigFlags::ENABLE_KEYBOARD_INTERRUPT, true);
    }

    if mouse_works {
        controller.enable_mouse()?;
        config.set(ControllerConfigFlags::DISABLE_MOUSE, false);
        config.set(ControllerConfigFlags::ENABLE_MOUSE_INTERRUPT, true);
    }

    // Step 7: Write the final configuration
    controller.write_config(config)?;

    Ok(controller)
}

/// Perform an operation with the PS/2 controller
///
/// This function takes a closure that is given a mutable reference to the controller
/// and returns the result of that closure. This ensures the controller is only
/// accessed while the mutex is held.
pub fn with_controller<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Controller) -> R,
{
    let mut lock = PS2_CONTROLLER.lock();
    (*lock).as_mut().map(f)
}

/// Check if the PS/2 controller is initialized
pub fn is_initialized() -> bool {
    CONTROLLER_INITIALIZED.load(Ordering::SeqCst)
}

/// Reset the PS/2 controller
pub fn reset() -> Result<(), &'static str> {
    if !is_initialized() {
        return Err("PS/2 controller not initialized");
    }

    match initialize_controller() {
        Ok(controller) => {
            let mut controller_lock = PS2_CONTROLLER.lock();
            *controller_lock = Some(controller);
            Ok(())
        }
        Err(_) => Err("Failed to reset PS/2 controller"),
    }
}
