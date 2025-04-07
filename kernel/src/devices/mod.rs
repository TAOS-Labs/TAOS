//! Device management and initialization.
//!
//! This module handles initialization and access to hardware devices including:
//! - Serial ports for debugging output
//! - Frame buffer for screen output
//! - Future device support will be added here

use crate::{memory::KERNEL_MAPPER, serial_println};
use limine::request::FramebufferRequest;
use pci::walk_pci_bus;
use sd_card::{find_sd_card, initalize_sd_card};
pub mod graphics;
use graphics::framebuffer::{self, colors};
pub mod keyboard;
pub mod mouse;
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
        let mut mapper = KERNEL_MAPPER.lock();
        initalize_sd_card(&sd_card_device, &mut mapper).unwrap();
        serial_println!("Sd card initialized");

        keyboard::init().expect("Failed to initialize keyboard");
        mouse::init().expect("Failed to initialize mouse");
    }
}
