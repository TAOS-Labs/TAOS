//! Device management and initialization.
//!
//! This module handles initialization and access to hardware devices including:
//! - Serial ports for debugging output
//! - Frame buffer for screen output
//! - Future device support will be added here

use crate::{memory::MAPPER, serial_println};
use pci::walk_pci_bus;
use sd_card::{find_sd_card, initalize_sd_card};
pub mod framebuffer;
use framebuffer::colors;
pub mod pci;
pub mod sd_card;
pub mod serial;

/// Initialize hardware devices.
///
/// This function handles early device initialization during boot.
/// Currently initializes:
/// - Frame buffer with basic test pattern
///
/// # Arguments
/// * `cpu_id` - ID of the CPU performing initialization. Only CPU 0
///   performs device initialization.
pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        if framebuffer::init() {
            serial_println!("Framebuffer initialized successfully");

            framebuffer::clear(colors::BLACK);

            framebuffer::with_framebuffer(|fb| {
                for i in 0..100 {
                    fb.set_pixel(i, i, colors::WHITE);
                }

                fb.fill_rect(framebuffer::Rect::new(20, 30, 100, 50), colors::RED);

                fb.fill_circle(200, 150, 40, colors::BLUE);

                fb.swap();
            });
        } else {
            serial_println!("Failed to initialize framebuffer");
        }

        let devices = walk_pci_bus();
        let sd_card_device =
            find_sd_card(&devices).expect("Build system currently sets up an sd-card");
        let mut mapper = MAPPER.lock();
        initalize_sd_card(&sd_card_device, &mut mapper).unwrap();
        serial_println!("Sd card initialized");
    }
}
