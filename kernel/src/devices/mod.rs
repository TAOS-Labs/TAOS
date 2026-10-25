//! Device management and initialization.
//!
//! This module handles initialization and access to hardware devices including:
//! - Serial ports for debugging output
//! - Frame buffer for screen output
//! - Future device support will be added here

use crate::{events::schedule_kernel, serial_println};
use pci::walk_pci_bus;
use sd_card::{find_sd_card, initalize_sd_card};
use xhci::{find_xhci_inferface, initalize_xhci_hub};
pub mod graphics;
use graphics::framebuffer::{self, colors};
pub mod audio;
pub mod mmio;
pub mod pci;
pub mod ps2_dev;
pub mod sd_card;
pub mod serial;
pub mod xhci;

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
        if graphics::init() {
            serial_println!("Framebuffer initialized successfully");

            framebuffer::clear(colors::BLACK);

            framebuffer::with_framebuffer(|fb| {
                for i in 0..100 {
                    fb.set_pixel(i, i, colors::WHITE);
                }

                fb.fill_rect(framebuffer::Rect::new(20, 30, 100, 50), colors::CYAN);

                fb.fill_circle(200, 150, 40, colors::BLUE);

                //text_renderer::draw_text(&mut fb, "Hello, world!", 10, 10, 20.0, colors::WHITE);

                fb.swap();
            });
        } else {
            serial_println!("Failed to initialize graphics");
        }

        // Uncomment to see some stuff
        // It takes a hot second though,
        // Like 15+ (parsing is apparently complex)
        // Might be worthwhile to shove off initialization of text renderer to a background kernel task?
        /*framebuffer::with_framebuffer(|mut fb| {
            text_renderer::draw_text(&mut fb, "Hello, world!", 10, 10, 20.0, colors::WHITE);
            fb.swap();
        });*/
        serial_println!("Text drawn");

        let devices = walk_pci_bus();

        match find_sd_card(&devices) {
            Some(device) => match initalize_sd_card(&device) {
                Ok(()) => serial_println!("SD card initialized"),
                Err(error) => serial_println!("SD card initialization failed: {:?}", error),
            },
            None => serial_println!("No SD card found; storage will be unavailable"),
        }

        match find_xhci_inferface(&devices) {
            Some(device) => match initalize_xhci_hub(&device) {
                Ok(()) => serial_println!("xHCI initialized"),
                Err(error) => serial_println!("xHCI initialization failed: {:?}", error),
            },
            None => serial_println!("No xHCI controller found; USB will be unavailable"),
        }

        if let Err(error) = ps2_dev::init() {
            serial_println!("PS/2 initialization failed: {}", error);
        }

        if let Err(error) = schedule_kernel(
            async {
                match audio::hda::IntelHDA::init().await {
                    Ok(hda) => {
                        serial_println!("HDA initialized at base address 0x{:X}", hda.base)
                    }
                    Err(error) => serial_println!("HDA initialization failed: {:?}", error),
                }
            },
            0,
        ) {
            serial_println!("Failed to schedule HDA initialization: {:?}", error);
        }
    }
}
