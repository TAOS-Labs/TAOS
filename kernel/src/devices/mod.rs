//! Device management and initialization.
//!
//! This module handles initialization and access to hardware devices including:
//! - Serial ports for debugging output
//! - Frame buffer for screen output
//! - Future device support will be added here

use crate::{memory::MAPPER, serial_println};
use limine::request::FramebufferRequest;
use pci::{print_pci_info, walk_pci_bus};
use sd_card::{find_sd_card, initalize_sd_card};
use xhci::{find_xhci_inferface, initalize_xhci_hub};
pub mod mmio;
pub mod pci;
pub mod sd_card;
pub mod serial;
pub mod xhci;

/// Framebuffer request to the bootloader.
/// Used to get access to video output capabilities.
///
/// TODO: Move to proper frame buffer implementation
#[used]
#[link_section = ".requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

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
        // Initialize frame buffer if available
        if let Some(framebuffer_response) = FRAMEBUFFER_REQUEST.get_response() {
            serial_println!("Found frame buffer");
            if let Some(framebuffer) = framebuffer_response.framebuffers().next() {
                // Draw a simple diagonal line test pattern
                // TODO: Replace with proper graphics initialization
                for i in 0..100_u64 {
                    let pixel_offset = i * framebuffer.pitch() + i * 4;
                    unsafe {
                        *(framebuffer.addr().add(pixel_offset as usize) as *mut u32) = 0xFFFFFFFF;
                    }
                }
            }
        }
        let devices = walk_pci_bus();
        for device in &devices {
            print_pci_info(&device.lock());
        }
        let sd_card_device =
            find_sd_card(&devices).expect("Build system currently sets up an sd-card");
        let xhci_device =
            find_xhci_inferface(&devices).expect("Build system currently sets up xhci device");

        let mut mapper = MAPPER.lock();
        initalize_sd_card(&sd_card_device, &mut mapper).unwrap();
        initalize_xhci_hub(&xhci_device, &mut mapper);

        serial_println!("Sd card initalized");
    }
}
