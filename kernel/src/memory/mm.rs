use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use spin::lock_api::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use bitflags::bitflags;
use crate::serial_println;

#[derive(Debug)]
pub struct Mm {
    pub vma_tree: Mutex<BTreeMap<usize, Arc<VmArea>>>,
    pub pml4_frame: PhysFrame<Size4KiB>,
}

impl Mm {
    pub fn new(pml4_frame: PhysFrame<Size4KiB>) -> Self {
        Mm {
            vma_tree: Mutex::new(BTreeMap::new()),
            pml4_frame,
        }
    }

    /// Insert a new VmArea into the VMA tree.
    pub fn insert_vma(&self, start: u64, end: u64, backing: u64, flags: VmAreaFlags) -> Arc<VmArea> {

        let left_vma = if start > 0 {
            Mm::find_vma(&self, start - 1)
        } else {
            None
        };

        let right_vma = Mm::find_vma(&self, end);

        let coalesce_left = start > 0 && left_vma.as_ref().map(|v| v.flags == flags && v.end == start).unwrap_or(false);
        let coalesce_right = right_vma.as_ref().map(|v| v.flags == flags && v.start == end).unwrap_or(false);

        if coalesce_left && coalesce_right {
            serial_println!("Coalescing both");
            let left_bor = left_vma.unwrap();
            let right_bor = right_vma.unwrap();
            let mut tree = self.vma_tree.lock();
            tree.remove(&(left_bor.start as usize));
            tree.remove(&(right_bor.start as usize));

            let new_vma = Arc::new(VmArea::new(left_bor.start, right_bor.end, backing, flags));

            tree.insert(left_bor.start as usize, new_vma.clone());

            new_vma.clone()
        } else if coalesce_left {
            serial_println!("Coalescing left");
            let left_bor = left_vma.unwrap();
            let mut tree = self.vma_tree.lock();
            tree.remove(&(left_bor.start as usize));

            serial_println!("Left start: {}", left_bor.start);

            let new_vma = Arc::new(VmArea::new(left_bor.start, end, backing, flags));

            serial_println!("{:#?}", new_vma);

            tree.insert(left_bor.start as usize, new_vma.clone());

            new_vma.clone()
        } else if coalesce_right {
            serial_println!("Coalescing right");
            let mut tree = self.vma_tree.lock();
            let right_bor = right_vma.unwrap();
            tree.remove(&(right_bor.start as usize));
            
            let new_vma = Arc::new(VmArea::new(start, right_bor.end, backing, flags));
            tree.insert(start as usize,new_vma.clone());

            new_vma.clone()
        } else {
            serial_println!("Coalescing none");
            let mut tree = self.vma_tree.lock();
            let new_vma = Arc::new(VmArea::new(start, end, backing, flags));
            tree.insert(start as usize, new_vma.clone());
            new_vma.clone()
        }
    }

    /// Remove the VmArea starting at the given address.
    pub fn remove_vma(&self, start: u64) -> Option<Arc<VmArea>> {
        let mut tree = self.vma_tree.lock();
        tree.remove(&(start as usize))
    }

    /// Find a VmArea that contains the given virtual address.
    pub fn find_vma(&self, addr: u64) -> Option<Arc<VmArea>> {
        let tree = self.vma_tree.lock();
        // Look for the area with the largest start address <= addr.
        let candidate = tree.range(..=addr as usize).next_back();
        if let Some((_, vma)) = candidate {
            if addr < vma.end {
                return Some(vma.clone());
            }
        }
        None
    }
}

impl Clone for Mm {
    fn clone(&self) -> Self {
        let vma_tree = self.vma_tree.lock().clone();
        Self {
            vma_tree: Mutex::new(vma_tree),
            pml4_frame: self.pml4_frame,
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct VmAreaFlags: u64 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXECUTE = 0b100;
    }
}

#[derive(Clone, Debug)]
pub struct VmArea {
    pub start: u64,
    pub end: u64,
    pub backing: u64,
    pub flags: VmAreaFlags
}

impl VmArea {
    pub fn new(start: u64, end: u64, backing: u64, flags: VmAreaFlags) -> Self {
        VmArea {
            start,
            end,
            backing,
            flags
        }
    }
}

// /// A composite key for reverse mappings, consisting of a VMA identifier and an offset.
// #[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
// pub struct AnonMappingKey {
//     pub vma_ptr: usize,
//     pub offset: u64,
// }

/// Reverse mapping chain entry that links a VMA and its offset to a physical page.
#[derive(Debug)]
pub struct AnonVmaChain {
    /// The VMA that maps this page
    pub vma: Arc<VmArea>,
    /// The page-aligned offset within the VMA
    pub offset: u64,
    /// The frame
    pub frame: Arc<PhysFrame>,
}

/// Anonymous VM area for managing reverse mappings for anonymous pages using a composite key.
#[derive(Debug)]
pub struct AnonVmArea {
    /// Reverse mappings keyed by (VMA pointer, offset).
    pub mappings: Mutex<BTreeMap<u64, Arc<AnonVmaChain>>>,
}

impl AnonVmArea {
    /// Create a new AnonVmArea with an empty mapping.
    pub fn new() -> Self {
        AnonVmArea {
            mappings: Mutex::new(BTreeMap::new()),
        }
    }

    /// Debug function to print all page to frame mappings
    pub fn print_mappings(&self) {
        for e in self.mappings.lock().iter() {
            serial_println!(
                "Key: {}, Offset: {}, Frame: {:#?}",
                e.0,
                e.1.offset,
                e.1.frame
            );
        }
    }

    /// Insert a new reverse mapping entry.
    pub fn insert_mapping(&self, chain: Arc<AnonVmaChain>) {
        // let key = AnonMappingKey {
        //     // Use the address of the VmArea (as usize) as the unique identifier.
        //     vma_ptr: Arc::as_ptr(&chain.vma) as usize,
        //     offset: chain.offset,
        // };
        let mut map = self.mappings.lock();
        map.insert(chain.offset, chain);
    }

    /// Remove and return the reverse mapping entry for the given VMA and offset.
    pub fn remove_mapping(&self, vma: &Arc<VmArea>, offset: u64) -> Option<Arc<AnonVmaChain>> {
        let mut map = self.mappings.lock();
        map.remove(&offset)
    }

    /// Find a reverse mapping entry for the given VMA and offset.
    pub fn find_mapping(&self, vma: &Arc<VmArea>, offset: u64) -> Option<Arc<AnonVmaChain>> {
        let map = self.mappings.lock();
        map.get(&offset).cloned()
    }
}

#[cfg(test)]
mod tests {
    use log::debug;
    use x86_64::{
        structures::paging::{Mapper, Page},
        PhysAddr, VirtAddr,
    };

    use crate::{
        constants::memory::PAGE_SIZE,
        memory::{
            frame_allocator::{alloc_frame, with_buddy_frame_allocator},
            paging::{create_mapping, remove_mapped_frame, update_mapping},
            KERNEL_MAPPER,
        },
    };

    use super::*;

    #[test_case]
    fn test_mm_vma_insert_find() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        // not testing backings here, can be 0
        // let vma1 = Arc::new(VmArea::new(0, 500, 0, VmAreaFlags::READ | VmAreaFlags::WRITE));
        // let vma2 = Arc::new(VmArea::new(500, 1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE));

        // Insert the VMAs.
        let vma1 = mm.insert_vma(0, 500, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);
        let vma2 = mm.insert_vma(600, 1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);

        // Test finding a VMA that covers a given address.
        let found1 = mm.find_vma(250);
        assert!(found1.is_some(), "Should find a VMA covering address 250");
        assert_eq!(found1.unwrap().start, 0);

        let found2 = mm.find_vma(750);
        assert!(found2.is_some(), "Should find a VMA covering address 750");
        assert_eq!(found2.unwrap().start, 600);
    }

    #[test_case]
    fn test_mm_vma_remove() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        // Create two VmArea instances.
        let vma = mm.insert_vma(0, 500, 123, VmAreaFlags::READ | VmAreaFlags::WRITE);

        let found = mm.find_vma(250);
        assert_eq!(found.unwrap().start, 0);

        let removed = mm.find_vma(mm.remove_vma(0).unwrap().start);
        assert!(removed.is_none());
    }

    /// Testcase to test whether correct frames are gotten after setting up
    /// an Anon_Vma backing
    ///
    /// Tests just 1 frame
    #[test_case]
    fn test_mm_anon_vm_backing() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        let anon_area = Arc::new(AnonVmArea::new());
        let backing_value = Arc::as_ptr(&anon_area) as u64;

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");

        let vm_area = mm.insert_vma(0, 0x1000, backing_value, VmAreaFlags::READ | VmAreaFlags::WRITE);

        // faulting_addresses and rounded down versions
        let faulting_address1: u64 = 0x500;

        let faulting_address1_round = (faulting_address1 - vm_area.start) & !(PAGE_SIZE as u64 - 1);

        // maps the vm_area and offset to the frame
        let chain1 = Arc::new(AnonVmaChain {
            vma: vm_area.clone(),
            offset: faulting_address1_round,
            frame: frame1.into(),
        });

        anon_area.insert_mapping(chain1.clone());

        // get the vma from some address access (as we would in pf handler)
        let found1 = mm.find_vma(faulting_address1).expect("Should find vma");
        assert_eq!(found1.backing, backing_value);

        let found1_anon_vma =
            anon_area.find_mapping(&found1, faulting_address1_round);

        assert_eq!(
            found1_anon_vma.unwrap().frame.start_address(),
            frame1.start_address()
        );
    }

    /// Tests the same thing as above, but with two different frames
    #[test_case]
    fn test_mm_anon_vm_backing2() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        // anon vm area to serve as backing for all vmas
        let anon_area = Arc::new(AnonVmArea::new());
        let backing_value = Arc::as_ptr(&anon_area) as u64;

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");
        let frame2 = alloc_frame().expect("Could not allocate PhysFrame");

        let vm_area = mm.insert_vma(0, 0x2000, backing_value, VmAreaFlags::READ | VmAreaFlags::WRITE);

        // faulting_addresses and rounded down versions
        let faulting_address1: u64 = 0x500;
        let faulting_address2: u64 = 0x1500;

        let faulting_address1_round = (faulting_address1 - vm_area.start) & !(PAGE_SIZE as u64 - 1);
        let faulting_address2_round = (faulting_address2 - vm_area.start) & !(PAGE_SIZE as u64 - 1);

        // maps the vm_area and offset to the frame
        let chain1 = Arc::new(AnonVmaChain {
            vma: vm_area.clone(),
            offset: faulting_address1_round,
            frame: frame1.into(),
        });

        // maps the vm_area and offset to the frame
        let chain2 = Arc::new(AnonVmaChain {
            vma: vm_area.clone(),
            offset: faulting_address2_round,
            frame: frame2.into(),
        });

        anon_area.insert_mapping(chain1.clone());
        anon_area.insert_mapping(chain2.clone());

        anon_area.print_mappings();

        // get the vma from some address access (as we would in pf handler)
        let found = mm.find_vma(faulting_address1).expect("Should find vma");
        assert_eq!(found.backing, backing_value);

        let found1_anon_vma = anon_area.find_mapping(&found, faulting_address1_round);

        assert_eq!(
            found1_anon_vma.unwrap().frame.start_address(),
            frame1.start_address()
        );

        // get the vma from some address access (as we would in pf handler)
        assert_eq!(found.backing, backing_value);

        let found2_anon_vma = anon_area.find_mapping(&found, faulting_address2_round);

        assert_eq!(
            found2_anon_vma.unwrap().frame.start_address(),
            frame2.start_address()
        );
    }

    /// Simulates multiple processes sharing memory by mapping multiple
    /// VMAs to the same anon_vma
    #[test_case]
    fn test_mm_multiple_vmas() {
        let pml4_frame1 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm1 = Mm::new(pml4_frame1);

        let pml4_frame2 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm2 = Mm::new(pml4_frame2);

        let anon_area = Arc::new(AnonVmArea::new());
        let backing_value = Arc::as_ptr(&anon_area) as u64;

        // two different vmas with the same backing
        // note: different start and end, so different faulting_addresses
        // correspond to same anon_vma
        let vm_area1 = mm1.insert_vma(0, 0x1000, backing_value, VmAreaFlags::READ | VmAreaFlags::WRITE);
        let vm_area2 = mm2.insert_vma(0x1000, 0x2000, backing_value, VmAreaFlags::READ | VmAreaFlags::WRITE);

        // fault here and map a frame (later done lazily, for now we just allocate a frame)
        let faulting_address1: u64 = 0x500;
        let faulting_address1_round =
            (faulting_address1 - vm_area1.start) & !(PAGE_SIZE as u64 - 1);

        let faulting_address2: u64 = 0x1500;
        let faulting_address2_round =
            (faulting_address2 - vm_area2.start) & !(PAGE_SIZE as u64 - 1);

        let frame = alloc_frame().expect("Could not get frame");

        // NOTE: This is why i think the VMA field is not necessary, but idk
        // maps the vm_area and offset to the frame
        let chain1 = Arc::new(AnonVmaChain {
            vma: vm_area1.clone(),
            offset: faulting_address1_round,
            frame: frame.into(),
        });

        anon_area.insert_mapping(chain1.clone());

        // get the vma from some address access (as we would in pf handler)
        let found1 = mm1.find_vma(faulting_address1).expect("Should find vma");
        let found2 = mm2.find_vma(faulting_address2).expect("Should find vma");
        assert_eq!(found1.backing, found2.backing);

        let found1_anon_vma =
            anon_area.find_mapping(&found1, faulting_address1_round);
        let found2_anon_vma =
            anon_area.find_mapping(&found2, faulting_address2_round);

        assert_eq!(
            found1_anon_vma.unwrap().frame.start_address(),
            found2_anon_vma.unwrap().frame.start_address()
        )
    }
    
    #[test_case]
    fn test_coalesce_left() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        let vma1 = mm.insert_vma(0, 0x1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);
        
        let got_vma1 = mm.find_vma(0x500);

        let vma2 = mm.insert_vma(0x1000, 0x2000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);

        let got_vma1_new = mm.find_vma(0x500);

        assert_eq!(got_vma1.unwrap().start, mm.find_vma(0x1500).unwrap().start);
    }

    #[test_case]
    fn test_coalesce_right() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        let vma1 = mm.insert_vma(0x1000, 0x2000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);
        let vma2 = mm.insert_vma(0x0, 0x1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);

        assert_eq!(0, mm.find_vma(0x1500).unwrap().start);
    }

    #[test_case]
    fn test_coalesce_both() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        let vma1 = mm.insert_vma(0x0, 0x1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);

        let got_vma1 = mm.find_vma(0x500).unwrap();

        let vma2 = mm.insert_vma(0x2000, 0x3000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);
        
        let vma3 = mm.insert_vma(0x1000, 0x2000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE);

        let got_vma2 = mm.find_vma(0x1500).unwrap();

        let got_vma3 = mm.find_vma(0x2500).unwrap();

        assert_eq!(got_vma1.start, got_vma2.start);
        assert_eq!(got_vma2.start, got_vma3.start);
    }
}