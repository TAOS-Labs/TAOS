use crate::memory::{frame_allocator::with_buddy_frame_allocator, HHDM_OFFSET};

use x86_64::{PhysAddr, VirtAddr};

#[derive(Clone)]
/// DMA buffer that is physically contiguous and mapped to virtual memory
pub struct DmaBuffer {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
}

impl DmaBuffer {
    /// Allocates `size` bytes of DMA-safe memory, shhould be page aligned
    pub fn new(size: usize) -> Option<Self> {
        let page_count = size.div_ceil(0x1000);

        let mut virt_addr = None;
        let mut phys_addr = None;
        let order = page_count.ilog2() + 1;

        with_buddy_frame_allocator(|f| {
            let frames = f.allocate_block(order.try_into().unwrap());
            for (idx, frame) in frames.iter().enumerate() {
                let temp_virt = *HHDM_OFFSET + frame.start_address().as_u64();

                if idx == 0 {
                    virt_addr = Some(temp_virt);
                    phys_addr = Some(frame.start_address());
                }

                unsafe {
                    core::ptr::write_bytes(temp_virt.as_mut_ptr::<u8>(), 0, 0x1000);
                }
            }
        });

        let virt = virt_addr?;
        let phys = phys_addr?;

        Some(Self {
            virt_addr: virt,
            phys_addr: phys,
            size: page_count * 0x1000,
        })
    }

    /// Zero out the buffer
    pub fn zero(&self) {
        unsafe {
            for i in 0..self.size {
                core::ptr::write_volatile(self.virt_addr.as_mut_ptr::<u8>().add(i), 0);
            }
        }
    }

    /// offsets the dma buffer by offset bytes
    pub fn offset(&mut self, offset: u64) {
        self.virt_addr += offset;
        self.phys_addr += offset;
        self.size -= offset as usize;
    }

    /// Interpret buffer as pointer to `T`
    pub fn as_ptr<T>(&self) -> *mut T {
        self.virt_addr.as_mut_ptr()
    }
}
