use crate::{
    memory::{frame_allocator::alloc_frame, paging::map_kernel_frame, HHDM_OFFSET, MAPPER},
    serial_println,
};

use x86_64::{
    structures::paging::{PageTableFlags, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

/// DMA buffer that is physically contiguous and mapped to virtual memory
pub struct DmaBuffer {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
}

impl DmaBuffer {
    /// Allocates `size` bytes of DMA-safe memory, shhould be page aligned
    pub fn new(size: usize) -> Option<Self> {
        let page_count = (size + 0xFFF) / 0x1000;
        serial_println!(
            "DmaBuffer::new() -> Requesting {} pages ({} bytes)",
            page_count,
            size
        );

        let mut virt_addr = None;
        let mut phys_addr = None;

        for i in 0..page_count {
            // serial_println!("Allocating frame {}", i);

            let frame = match alloc_frame() {
                Some(f) => f,
                None => {
                    serial_println!("Failed to allocate frame {}", i);
                    if i == 0 {
                        return None;
                    } else {
                        let fallback_size = i * 0x1000;
                        serial_println!("Falling back to {} bytes", fallback_size);
                        return DmaBuffer::new(fallback_size);
                    }
                }
            };

            // serial_println!("Got frame {} at physical address 0x{:X}", i, frame.start_address().as_u64());

            let temp_virt = *HHDM_OFFSET + frame.start_address().as_u64();

            if i == 0 {
                virt_addr = Some(temp_virt);
                phys_addr = Some(frame.start_address()); // now it works, since no shadowing
            }

            // serial_println!("Using virtual address 0x{:X} for page {}", temp_virt.as_u64(), i);

            unsafe {
                core::ptr::write_bytes(temp_virt.as_mut_ptr::<u8>(), 0, 0x1000);
            }
        }

        let virt = virt_addr?;
        let phys = phys_addr?;

        serial_println!(
            "DMA buffer allocated: virt=0x{:X}, phys=0x{:X}, size={} bytes",
            virt.as_u64(),
            phys.as_u64(),
            page_count * 0x1000
        );

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

    /// Interpret buffer as pointer to `T`
    pub fn as_ptr<T>(&self) -> *mut T {
        self.virt_addr.as_mut_ptr()
    }
}
