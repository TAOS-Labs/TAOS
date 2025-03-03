//! Frame allocators for use in allocation and deallocation
//! Contains a GlobalFrameAllocator, which is a wrapper around
//! the BootIntoFrameAllocator and the BitmapFrameAllocator

use crate::memory::{
    bitmap_frame_allocator::BitmapFrameAllocator, boot_frame_allocator::BootIntoFrameAllocator,
    buddy_frame_allocator::BuddyFrameAllocator,
};
use spin::Mutex;

use x86_64::structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size4KiB};

/// Global frame allocator that makes it so we just have one actual allocator throughout codebase
/// Requires some basic synchronization
pub static FRAME_ALLOCATOR: Mutex<Option<GlobalFrameAllocator>> = Mutex::new(None);

/// Enum of supported allocators
pub enum GlobalFrameAllocator {
    Boot(BootIntoFrameAllocator),
    Bitmap(BitmapFrameAllocator),
    Buddy(BuddyFrameAllocator),
}

unsafe impl FrameAllocator<Size4KiB> for GlobalFrameAllocator {
    /// Global allocator that allocates a frame using either the boot frame allocator or the bitmap
    /// depending on what the current selected allocator is
    ///
    /// # Returns
    /// The allocated frame
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        match self {
            GlobalFrameAllocator::Boot(ref mut boot_alloc) => boot_alloc.allocate_frame(),
            GlobalFrameAllocator::Bitmap(ref mut bitmap_alloc) => bitmap_alloc.allocate_frame(),
            GlobalFrameAllocator::Buddy(ref mut buddy_alloc) => buddy_alloc.allocate_frame(),
        }
    }
}

impl FrameDeallocator<Size4KiB> for GlobalFrameAllocator {
    /// Global deallocator that calls either the boot frame allocator or the bitmap
    /// depending on what the current selected allocator is
    ///
    /// # Arguments
    /// * `frame`: the frame to deallocate
    ///
    /// # Safety
    /// The frame must be ensured to be allocated
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        match self {
            GlobalFrameAllocator::Boot(ref mut boot_alloc) => boot_alloc.deallocate_frame(frame),
            GlobalFrameAllocator::Bitmap(ref mut bitmap_alloc) => {
                bitmap_alloc.deallocate_frame(frame)
            }
            GlobalFrameAllocator::Buddy(ref mut buddy_alloc) => buddy_alloc.deallocate_frame(frame),
        }
    }
}

/// Exposed function to allocate a frame that runs the global's allocate_frame
///
/// # Returns
/// The allocated frame
pub fn alloc_frame() -> Option<PhysFrame> {
    with_generic_allocator(|allocator| allocator.allocate_frame())
}

/// Exposed function to deallocate a frame that runs the global's deallocate_frame
///
/// # Arguments
/// * `frame`: The frame to deallocate
pub fn dealloc_frame(frame: PhysFrame<Size4KiB>) {
    with_generic_allocator(|allocator| unsafe { allocator.deallocate_frame(frame) })
}

/// Gives access to the bitmap frame allocator to any passed in closure
/// Example:
/// with_buddy_frame_allocator(|allocator| {
///     // code to run
/// })
///
/// Arguments:
///
/// * `f`: The closure to run
pub fn with_buddy_frame_allocator<F, R>(f: F) -> R
where
    F: FnOnce(&mut BuddyFrameAllocator) -> R,
{
    let mut guard = FRAME_ALLOCATOR.lock();
    let alloc = match &mut *guard {
        Some(GlobalFrameAllocator::Buddy(alloc)) => alloc,
        _ => panic!("Allocator is not a BuddyFrameAllocator"),
    };
    f(alloc)
}

/// Gives access to the bitmap frame allocator to any passed in closure
/// Example:
/// with_bitmap_frame_allocator(|allocator| {
///     // code to run
/// })
///
/// Arguments:
///
/// * `f`: The closure to run
pub fn with_bitmap_frame_allocator<F, R>(f: F) -> R
where
    F: FnOnce(&mut BitmapFrameAllocator) -> R,
{
    let mut guard = FRAME_ALLOCATOR.lock();
    let alloc = match &mut *guard {
        Some(GlobalFrameAllocator::Bitmap(alloc)) => alloc,
        _ => panic!("Allocator is not a BitmapFrameAllocator"),
    };
    f(alloc)
}

/// Gives access to the boot into frame allocator to any passed in closure
/// Example:
/// with_boot_into_frame_allocator(|allocator| {
///     // code to run
/// })
///
/// Arguments:
///
/// * `f`: The closure to run
pub fn with_boot_into_frame_allocator<F, R>(f: F) -> R
where
    F: FnOnce(&mut BootIntoFrameAllocator) -> R,
{
    let mut guard = FRAME_ALLOCATOR.lock();
    let alloc = match &mut *guard {
        Some(GlobalFrameAllocator::Boot(alloc)) => alloc,
        _ => panic!("Allocator is not a BootIntoFrameAllocator"),
    };
    f(alloc)
}

/// Gives access to the global frame allocator to any passed in closure
/// Example:
/// with_generic_allocator(|allocator| {
///     // code to run
/// })
///
/// Arguments:
///
/// * `f`: The closure to run
pub fn with_generic_allocator<F, R>(f: F) -> R
where
    F: FnOnce(&mut GlobalFrameAllocator) -> R,
{
    let mut guard = FRAME_ALLOCATOR.lock();
    if let Some(ref mut allocator) = *guard {
        f(allocator)
    } else {
        panic!("Allocator does not exist.");
    }
}
