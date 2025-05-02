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

        let sd_card_device =
            find_sd_card(&devices).expect("Build system currently sets up an sd-card");

        initalize_sd_card(&sd_card_device).unwrap();
        serial_println!("Sd card initialized");

        let xhci_device =
            find_xhci_inferface(&devices).expect("Build system currently sets up xhci device");
        initalize_xhci_hub(&xhci_device).unwrap();

        ps2_dev::init();

        serial_println!("before init audio");
        schedule_kernel(
            async {
                if let Some(hda) = audio::hda::IntelHDA::init().await {
                    serial_println!("HDA initialized at base address 0x{:X}", hda.base);
                } else {
                    serial_println!("HDA controller not found.");
                }
            },
            0,
        );
    }
}
