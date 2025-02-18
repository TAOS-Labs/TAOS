pub mod bitmap_frame_allocator;
pub mod boot_frame_allocator;
pub mod frame_allocator;
pub mod heap;
pub mod paging;

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
    pub static ref MAPPER: Mutex<OffsetPageTable<'static>> = Mutex::new(unsafe { paging::init() });
    pub static ref HHDM_OFFSET: VirtAddr = VirtAddr::new(
        HHDM_REQUEST
            .get_response()
            .expect("HHDM request failed")
            .offset()
    );
}

pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        unsafe {
            *FRAME_ALLOCATOR.lock() =
                Some(GlobalFrameAllocator::Boot(BootIntoFrameAllocator::init()));
        }

        unsafe {
            // Must be done after enabling long mode + paging
            Efer::update(|flags| {
                flags.insert(EferFlags::NO_EXECUTE_ENABLE);
            });
        }
        let mut mapper = MAPPER.lock();
        heap::init_heap(&mut *mapper).expect("Failed to initialize heap");
    }
}
