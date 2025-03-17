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

use alloc::sync::Arc;
use boot_frame_allocator::BootIntoFrameAllocator;
use frame_allocator::{alloc_frame, GlobalFrameAllocator, FRAME_ALLOCATOR};
use lazy_static::lazy_static;
use limine::request::HhdmRequest;
use mm::{AnonVmArea, Mm, VmAreaFlags, VmaChain};
use spin::Mutex;
use x86_64::{
    registers::model_specific::{Efer, EferFlags}, structures::paging::{OffsetPageTable, PhysFrame}, PhysAddr, VirtAddr
};

use crate::serial_println;

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
        HHDM_REQUEST
            .get_response()
            .expect("HHDM request failed")
            .offset()
    );
}

/// Initializes the global frame allocator and kernel heap
///
/// * `cpu_id`: The CPU to initialize for. We only want to initialize a frame allocator for cpuid 0
pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        unsafe {
            *FRAME_ALLOCATOR.lock() =
                Some(GlobalFrameAllocator::Boot(BootIntoFrameAllocator::init()));
        }

        unsafe {
            // Must be done after enabling long mode + paging
            // Allows us to mark pages as unexecutable for security
            Efer::update(|flags| {
                flags.insert(EferFlags::NO_EXECUTE_ENABLE);
            });
        }
        heap::init_heap().expect("Failed to initializen heap");
    }

    let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
    let mm1 = Mm::new(pml4_frame);
    
    let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x2000));
    let mm2 = Mm::new(pml4_frame);

    let anon_area1 = Arc::new(AnonVmArea::new());
    let anon_area2 = Arc::new(AnonVmArea::new());

    // add frame mappings as they should be right now
    anon_area1.insert_mapping(Arc::new(VmaChain::new(
        0x0000,
        Arc::new(alloc_frame().unwrap()),
    )));
    anon_area1.insert_mapping(Arc::new(VmaChain::new(
        0x1000,
        Arc::new(alloc_frame().unwrap()),
    )));

    anon_area2.insert_mapping(Arc::new(VmaChain::new(
        0x0000,
        Arc::new(alloc_frame().unwrap()),
    )));
    anon_area2.insert_mapping(Arc::new(VmaChain::new(
        0x1000,
        Arc::new(alloc_frame().unwrap()),
    )));
    anon_area2.insert_mapping(Arc::new(VmaChain::new(
        0x2000,
        Arc::new(alloc_frame().unwrap()),
    )));
    anon_area2.insert_mapping(Arc::new(VmaChain::new(
        0x3000,
        Arc::new(alloc_frame().unwrap()),
    )));
    anon_area2.insert_mapping(Arc::new(VmaChain::new(
        0x4000,
        Arc::new(alloc_frame().unwrap()),
    )));

    mm1.with_vma_tree_mutable(|tree| {
        Mm::insert_vma(
            tree,
            0x5000,
            0x7000,
            anon_area1.clone(),
            0,
            VmAreaFlags::WRITABLE,
        );
    });
    serial_println!("Got here 1");

    mm2.with_vma_tree_mutable(|tree| {
        Mm::insert_vma(
            tree,
            0,
            0x2000,
            anon_area1.clone(),
            0,
            VmAreaFlags::WRITABLE,
        );
    });
    serial_println!("Got here 2");

    mm1.with_vma_tree_mutable(|tree| {
        Mm::insert_vma(
            tree,
            0,
            0x5000,
            anon_area2.clone(),
            0,
            VmAreaFlags::WRITABLE,
        );
    });
    serial_println!("Got here 3");



    mm1.with_vma_tree(|tree| {
        let final_vma = Mm::find_vma(0, tree).unwrap();
        let final_vma_locked = final_vma.lock();

        serial_println!("Final Vma start is: {:X}", final_vma_locked.start);
        serial_println!("Final Vma end is: {:X}", final_vma_locked.end);
        serial_println!("Final Vma index_offset is: {:X}", final_vma_locked.index_offset);

        assert_eq!(final_vma_locked.end, 0x7000);
    })
}
