use core::ptr::write_volatile;

/// Intel HDA Buffer Descriptor (BDL) Entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BdlEntry {
    pub address: u32,
    pub address_high: u32,
    pub length: u32,
    pub flags: u32,
}

impl BdlEntry {
    pub const IOC_FLAG: u32 = 1;

    pub fn new(addr: u64, len: u32, interrupt_on_completion: bool) -> Self {
        BdlEntry {
            address: addr as u32,
            address_high: (addr >> 32) as u32,
            length: len,
            flags: if interrupt_on_completion {
                Self::IOC_FLAG
            } else {
                0
            },
        }
    }
}
/// Write BDL entries into the physical memory region (must be DMA accessible)
///
/// # Safety
/// preforms a pointer write
pub unsafe fn setup_bdl(
    bdl_virt_addr: *mut BdlEntry,
    buffer_phys_start: u64,
    total_size: u32,
    entry_size: u32,
) -> usize {
    let num_entries_needed = total_size.div_ceil(entry_size) as u64;
    let num_entries = if num_entries_needed > 256 {
        256
    } else {
        num_entries_needed
    };

    let mut offset = 0;

    for i in 0..num_entries {
        let phys_addr = buffer_phys_start + offset as u64;
        let is_last = i == num_entries - 1;
        let entry = BdlEntry::new(phys_addr, entry_size, is_last);

        unsafe {
            write_volatile(bdl_virt_addr.add(i as usize), entry);
        }

        offset += entry_size;
    }

    num_entries as usize
}
