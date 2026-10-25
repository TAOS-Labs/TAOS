//! The Virtual memory system
//! Initializes a kernel heap and the frame allocators
//! Provides an interface for paging and mapping frames of memory
//! Implements TLB shootdowns

pub mod bitmap_frame_allocator;
pub mod boot_frame_allocator;
pub mod buddy_frame_allocator;
pub mod frame_allocator;
pub mod heap;
pub mod mm;
pub mod page_fault;
pub mod paging;
pub mod tlb;

use boot_frame_allocator::BootIntoFrameAllocator;
use frame_allocator::{GlobalFrameAllocator, FRAME_ALLOCATOR};
use lazy_static::lazy_static;
use limine::request::HhdmRequest;
use spin::Mutex;
use x86_64::{
    registers::model_specific::{Efer, EferFlags},
    structures::paging::OffsetPageTable,
    VirtAddr,
};

#[used]
#[link_section = ".requests"]
pub static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

extern "C" {
    static _kernel_end: u64;
}

lazy_static! {
    // The kernel mapper
    pub static ref KERNEL_MAPPER: Mutex<OffsetPageTable<'static>> = Mutex::new(unsafe { paging::init() });
    // Start of kernel virtual memory
    pub static ref HHDM_OFFSET: VirtAddr = VirtAddr::new(
        match HHDM_REQUEST.get_response() {
            Some(response) => response.offset(),
            None => {
                crate::serial_println!("Bootloader did not provide the required HHDM response");
                crate::idle_loop();
            }
        }
    );
}

/// Initializes the global frame allocator and kernel heap
///
/// * `cpu_id`: The CPU to initialize for. We only want to initialize a frame allocator for cpuid 0
pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        unsafe {
            let Some(allocator) = BootIntoFrameAllocator::init() else {
                crate::serial_println!("Bootloader memory information is unavailable");
                crate::idle_loop();
            };
            *FRAME_ALLOCATOR.lock() = Some(GlobalFrameAllocator::Boot(allocator));
        }

        unsafe {
            // Must be done after enabling long mode + paging
            // Allows us to mark pages as unexecutable for security
            Efer::update(|flags| {
                flags.insert(EferFlags::NO_EXECUTE_ENABLE);
            });
        }
        if let Err(error) = heap::init_heap() {
            crate::serial_println!("Failed to initialize heap: {:?}", error);
            crate::idle_loop();
        }
    }
}
