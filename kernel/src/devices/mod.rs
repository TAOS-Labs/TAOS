use crate::serial_println;
use limine::request::FramebufferRequest;

pub mod serial;

// TODO: Fix when we have a proper frame buffer
#[used]
#[link_section = ".requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        if let Some(framebuffer_response) = FRAMEBUFFER_REQUEST.get_response() {
            serial_println!("Found frame buffer");
            if let Some(framebuffer) = framebuffer_response.framebuffers().next() {
                for i in 0..100_u64 {
                    let pixel_offset = i * framebuffer.pitch() + i * 4;
                    unsafe {
                        *(framebuffer.addr().add(pixel_offset as usize) as *mut u32) = 0xFFFFFFFF;
                    }
                }
            }
        }
    }
}
