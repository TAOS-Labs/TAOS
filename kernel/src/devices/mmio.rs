#[repr(transparent)]
pub(crate) struct MMioPtr<T>(pub *mut T);

unsafe impl<T> Send for MMioPtr<T> {}

impl<T> MMioPtr<T> {
    pub unsafe fn read(&self) -> T {
        core::ptr::read_volatile(self.0)
    }

    #[allow(dead_code)]
    pub unsafe fn read_unaliged(&self) -> T {
        core::ptr::read_unaligned(self.0)
    }

    pub unsafe fn write(&self, val: T) {
        core::ptr::write_volatile(self.0, val);
    }

    #[allow(dead_code)]
    pub unsafe fn write_unaligned(&self, val: T) {
        core::ptr::write_unaligned(self.0, val);
    }

    pub fn as_ptr(&self) -> *mut T {
        self.0
    }

    #[allow(dead_code)]
    pub unsafe fn add<EndType>(&self, offset: usize) -> MMioPtr<EndType> {
        MMioPtr(self.0.add(offset) as *mut EndType)
    }
}

#[repr(transparent)]
pub(crate) struct MMioConstPtr<T>(pub *const T);

unsafe impl<T> Send for MMioConstPtr<T> {}

impl<T> MMioConstPtr<T> {
    #[allow(dead_code)]
    pub unsafe fn read(&self) -> T {
        core::ptr::read_volatile(self.0)
    }

    #[allow(dead_code)]
    pub unsafe fn read_unaligned(&self) -> T {
        core::ptr::read_unaligned(self.0)
    }

    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const T {
        self.0
    }

    #[allow(dead_code)]
    pub unsafe fn add<EndType>(&self, offset: usize) -> MMioConstPtr<EndType> {
        MMioConstPtr(self.0.add(offset) as *mut EndType)
    }
}

use x86_64::{
    structures::paging::{
        mapper::{MappedFrame, TranslateResult},
        Mapper, OffsetPageTable, Page, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
        Translate,
    },
    PhysAddr, VirtAddr,
};

use crate::memory::paging;

/// An error occured when setting up a frame as uncacheable
#[derive(Debug)]
pub struct MMIOError;

/// Maps the requested_phys_addr as an uncacheable page above hhdm offset
pub fn map_page_as_uncacheable(
    requested_phys_addr: PhysAddr,
    mapper: &mut OffsetPageTable,
) -> Result<VirtAddr, MMIOError> {
    let offset = mapper.phys_offset().as_u64();
    let mut offset_bar = requested_phys_addr.as_u64() + offset;
    let translate_result = mapper.translate(VirtAddr::new(offset_bar));
    match translate_result {
        TranslateResult::Mapped {
            frame,
            offset: _,
            flags,
        } => match frame {
            MappedFrame::Size4KiB(_) => {
                // debug_println!("mapped 4KB from {:X}", requested_phys_addr);
                let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(offset_bar));
                unsafe {
                    mapper
                        .update_flags(
                            page,
                            flags | PageTableFlags::NO_CACHE | PageTableFlags::WRITABLE,
                        )
                        .map_err(|_| MMIOError)?
                        .flush();
                }
            }
            MappedFrame::Size2MiB(_) => {
                // debug_println!("mapped 2MB from {:X}", requested_phys_addr);
                let page: Page<Size2MiB> = Page::containing_address(VirtAddr::new(offset_bar));
                unsafe {
                    mapper
                        .update_flags(
                            page,
                            flags | PageTableFlags::NO_CACHE | PageTableFlags::WRITABLE,
                        )
                        .map_err(|_| MMIOError)?
                        .flush();
                }
            }
            MappedFrame::Size1GiB(_) => {
                // debug_println!("mapped 1GB");
                let page: Page<Size1GiB> = Page::containing_address(VirtAddr::new(offset_bar));
                unsafe {
                    mapper
                        .update_flags(
                            page,
                            flags | PageTableFlags::NO_CACHE | PageTableFlags::WRITABLE,
                        )
                        .map_err(|_| MMIOError)?
                        .flush();
                }
            }
        },
        TranslateResult::InvalidFrameAddress(_) => {
            panic!("Invalid physical address in SD BAR")
        }
        TranslateResult::NotMapped => {
            // debug_println!("notmapped");
            let bar_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(requested_phys_addr);
            let new_va = paging::map_kernel_frame(
                mapper,
                bar_frame,
                PageTableFlags::PRESENT | PageTableFlags::NO_CACHE | PageTableFlags::WRITABLE,
            );
            offset_bar = new_va.as_u64();
        }
    }
    Result::Ok(VirtAddr::new(offset_bar))
}

pub fn zero_out_page(page: Page) {
    let mut va: *mut u8 = page.start_address().as_mut_ptr();
    let mut n = 0;
    while n < page.size() {
        unsafe {
            core::ptr::write_volatile(va, 0);
            va = va.add(1);
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use core::ptr::copy_nonoverlapping;

    use x86_64::structures::paging::FrameAllocator;

    use super::*;
    use crate::{
        constants::memory::PAGE_SIZE,
        memory::{frame_allocator::FRAME_ALLOCATOR, KERNEL_MAPPER},
    };

    #[test_case]
    async fn test_zero_out_page_4kib() {
        let mut mapper = KERNEL_MAPPER.lock();
        let mut allocator_tmp = FRAME_ALLOCATOR.lock();
        let mut frames: [Option<PhysFrame>; 3] = [Option::None; 3];
        match *allocator_tmp {
            Option::Some(ref mut new_allocator) => {
                frames[0] = new_allocator.allocate_frame();
                frames[1] = new_allocator.allocate_frame();
                frames[2] = new_allocator.allocate_frame();
            }
            _ => panic!("We shoould have a frame allocator at this point"),
        };
        let addr_1 =
            map_page_as_uncacheable(frames[0].unwrap().start_address(), &mut mapper).unwrap();
        let addr_2 =
            map_page_as_uncacheable(frames[1].unwrap().start_address(), &mut mapper).unwrap();
        let addr_3 =
            map_page_as_uncacheable(frames[2].unwrap().start_address(), &mut mapper).unwrap();

        let page: [u8; PAGE_SIZE] = [255; PAGE_SIZE];
        let page_actual = Page::containing_address(VirtAddr::new(addr_2.as_u64()));

        let addr_1_ptr: *mut u8 = addr_1.as_mut_ptr::<u8>();
        let addr_2_ptr: *mut u8 = addr_2.as_mut_ptr::<u8>();
        let addr_3_ptr: *mut u8 = addr_3.as_mut_ptr::<u8>();

        unsafe { copy_nonoverlapping(page.as_ptr(), addr_1_ptr, PAGE_SIZE) };
        unsafe { copy_nonoverlapping(page.as_ptr(), addr_2_ptr, PAGE_SIZE) };
        unsafe { copy_nonoverlapping(page.as_ptr(), addr_3_ptr, PAGE_SIZE) };

        let mut verify_buff: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
        zero_out_page(page_actual);
        unsafe { copy_nonoverlapping(addr_1_ptr, verify_buff.as_mut_ptr(), PAGE_SIZE) };
        assert!(verify_buff == [255; PAGE_SIZE]);
        unsafe { copy_nonoverlapping(addr_2_ptr, verify_buff.as_mut_ptr(), PAGE_SIZE) };
        assert!(verify_buff == [0; PAGE_SIZE]);
        unsafe { copy_nonoverlapping(addr_3_ptr, verify_buff.as_mut_ptr(), PAGE_SIZE) };
        assert!(verify_buff == [255; PAGE_SIZE]);
    }
}
