use crate::serial_println;
use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use bitflags::bitflags;
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

type VmaTree = BTreeMap<usize, Arc<Mutex<VmArea>>>;

#[derive(Debug)]
pub struct Mm {
    pub vma_tree: Mutex<VmaTree>,
    pub pml4_frame: PhysFrame<Size4KiB>,
}

impl Clone for Mm {
    fn clone(&self) -> Self {
        self.with_vma_tree(|tree| Mm {
            vma_tree: Mutex::new(tree.clone()),
            pml4_frame: self.pml4_frame,
        })
    }
}

impl Mm {
    pub fn new(pml4_frame: PhysFrame<Size4KiB>) -> Self {
        Mm {
            vma_tree: Mutex::new(BTreeMap::new()),
            pml4_frame,
        }
    }

    /// Insert a new VmArea into the VMA tree.
    pub fn insert_vma(
        &self,
        tree: &mut VmaTree,
        start: u64,
        end: u64,
        backing: Arc<AnonVmArea>,
        flags: VmAreaFlags,
        anon: bool,
    ) -> Arc<Mutex<VmArea>> {
        let left_vma = if start > 0 {
            Mm::find_vma(&self, start - 1, tree)
        } else {
            None
        };

        let right_vma = Mm::find_vma(&self, end, tree);
        let coalesce_left = if start > 0 {
            left_vma
                .as_ref()
                .map(|v| {
                    let guard = v.lock();
                    guard.flags == flags && guard.end == start
                })
                .unwrap_or(false)
        } else {
            false
        };

        let coalesce_right = right_vma
            .as_ref()
            .map(|v| {
                let guard = v.lock();
                guard.flags == flags && guard.start == end
            })
            .unwrap_or(false);

        // TODO: Deal with backing
        if coalesce_left && coalesce_right {
            let left_bor = left_vma.unwrap();
            let right_bor = right_vma.unwrap();
            tree.remove(&(left_bor.lock().start as usize));
            tree.remove(&(right_bor.lock().start as usize));

            let new_vma = Arc::new(Mutex::new(VmArea::new(
                left_bor.lock().start,
                right_bor.lock().end,
                backing,
                flags,
                anon,
            )));

            tree.insert(left_bor.lock().start as usize, new_vma.clone());

            new_vma.clone()
        } else if coalesce_left {
            let left_vma_unwrapped = left_vma.unwrap();
            let left_bor = left_vma_unwrapped.lock();
            tree.remove(&(left_bor.start as usize));
            let new_vma = Arc::new(Mutex::new(VmArea::new(
                left_bor.start,
                end,
                left_bor.backing.clone(),
                flags,
                anon,
            )));

            tree.insert(left_bor.start as usize, new_vma.clone());

            new_vma.clone()
        } else if coalesce_right {
            let right_vma_unwrapped = right_vma.unwrap();
            let right_bor = right_vma_unwrapped.lock();
            tree.remove(&(right_bor.start as usize));

            let new_vma = Arc::new(Mutex::new(VmArea::new(
                start,
                right_bor.end,
                backing,
                flags,
                anon,
            )));
            tree.insert(start as usize, new_vma.clone());

            new_vma.clone()
        } else {
            let new_vma = Arc::new(Mutex::new(VmArea::new(start, end, backing, flags, anon)));
            tree.insert(start as usize, new_vma.clone());
            new_vma.clone()
        }
    }

    /// Remove the VmArea starting at the given address.
    pub fn remove_vma(&self, start: u64, tree: &mut VmaTree) -> Option<Arc<Mutex<VmArea>>> {
        tree.remove(&(start as usize))
    }

    /// Find a VmArea that contains the given virtual address.
    pub fn find_vma(&self, addr: u64, tree: &VmaTree) -> Option<Arc<Mutex<VmArea>>> {
        // Look for the area with the largest start address <= addr.
        let candidate = tree.range(..=addr as usize).next_back();
        if let Some((_, vma)) = candidate {
            if addr < vma.lock().end {
                return Some(vma.clone());
            }
        }
        None
    }

    /// Debug fn to print vma
    pub fn print_vma(&self, tree: &VmaTree) {
        for (i, vma) in tree.iter().enumerate() {
            serial_println!("VMA {}: {:#?}", i, vma.1.lock());
        }
    }

    pub fn with_vma_tree_mutable<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut VmaTree) -> R,
    {
        // Lock the vma_tree. In production code consider handling the poison error.
        let mut tree = self.vma_tree.lock();
        f(&mut tree)
    }

    pub fn with_vma_tree<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&VmaTree) -> R,
    {
        // Lock the vma_tree. In production code consider handling the poison error.
        let tree = self.vma_tree.lock();
        f(&tree)
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct VmAreaFlags: u64 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXECUTE = 0b100;
        const SHARED = 0b1000; // If 1, shared. If 0, private (COW)
        const GROWS_DOWN = 0b1_0000; // Stack
    }
}

#[derive(Clone, Debug)]
pub struct VmArea {
    pub start: u64,
    pub end: u64,
    pub backing: Arc<AnonVmArea>,
    pub flags: VmAreaFlags,
    pub anon: bool,
}

impl VmArea {
    pub fn new(
        start: u64,
        end: u64,
        backing: Arc<AnonVmArea>,
        flags: VmAreaFlags,
        anon: bool,
    ) -> Self {
        VmArea {
            start,
            end,
            backing,
            flags,
            anon,
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
    // pub vma: Arc<VmArea>,
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
    pub fn remove_mapping(&self, offset: u64) -> Option<Arc<AnonVmaChain>> {
        let mut map = self.mappings.lock();
        map.remove(&offset)
    }

    /// Find a reverse mapping entry for the given VMA and offset.
    pub fn find_mapping(&self, offset: u64) -> Option<Arc<AnonVmaChain>> {
        let map = self.mappings.lock();
        map.get(&offset).cloned()
    }
}

// #[cfg(test)]
// mod tests {
//     use log::debug;
//     use x86_64::{
//         structures::paging::{Mapper, Page},
//         PhysAddr, VirtAddr,
//     };

//     use crate::{
//         constants::memory::PAGE_SIZE,
//         memory::{
//             frame_allocator::{alloc_frame, with_buddy_frame_allocator},
//             paging::{create_mapping, remove_mapped_frame, update_mapping},
//             KERNEL_MAPPER,
//         },
//     };

//     use super::*;

//     #[test_case]
//     fn test_mm_vma_insert_find() {
//         // Create a dummy PML4 frame.
//         let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm = Mm::new(pml4_frame);

//         mm.with_vma_tree_mutable(|tree| {
//             let vma1 = mm.insert_vma(tree, 0, 500, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true);
//             let vma2 = mm.insert_vma(tree, 600, 1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true);
//             // Test finding a VMA that covers a given address.
//             let found1 = mm.find_vma(250, tree);
//             assert!(found1.is_some(), "Should find a VMA covering address 250");
//             assert_eq!(found1.unwrap().start, 0);

//             let found2 = mm.find_vma(750, tree);
//             assert!(found2.is_some(), "Should find a VMA covering address 750");
//             assert_eq!(found2.unwrap().start, 600);
//         });
//     }

//     #[test_case]
//     fn test_mm_vma_remove() {
//         // Create a dummy PML4 frame.
//         let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm = Mm::new(pml4_frame);

//         mm.with_vma_tree_mutable(|tree| {
//             // Create two VmArea instances.
//             let vma = mm.insert_vma(tree, 0, 500, 123, VmAreaFlags::READ | VmAreaFlags::WRITE, true);

//             let found = mm.find_vma(250, tree);
//             assert_eq!(found.unwrap().start, 0);

//             let removed = mm.find_vma(mm.remove_vma(tree, 0).unwrap().start, tree);
//             assert!(removed.is_none());
//         })
//     }

//     /// Testcase to test whether correct frames are gotten after setting up
//     /// an Anon_Vma backing
//     ///
//     /// Tests just 1 frame
//     #[test_case]
//     fn test_mm_anon_vm_backing() {
//         let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm = Mm::new(pml4_frame);

//         let anon_area = Arc::new(AnonVmArea::new());
//         let backing_value = Arc::as_ptr(&anon_area) as u64;

//         let frame1 = alloc_frame().expect("Could not allocate PhysFrame");

//         let vm_area = mm.with_vma_tree_mutable(|tree| {
//             mm.insert_vma(tree, 0, 0x1000, backing_value, VmAreaFlags::READ | VmAreaFlags::WRITE, true)
//         });

//         // faulting_addresses and rounded down versions
//         let faulting_address1: u64 = 0x500;

//         let faulting_address1_round = (faulting_address1 - vm_area.start) & !(PAGE_SIZE as u64 - 1);

//         // maps the vm_area and offset to the frame
//         let chain1 = Arc::new(AnonVmaChain {
//             offset: faulting_address1_round,
//             frame: frame1.into(),
//         });

//         anon_area.insert_mapping(chain1.clone());

//         // get the vma from some address access (as we would in pf handler)
//         mm.with_vma_tree(|tree| {
//             let found1 = mm.find_vma(faulting_address1, tree).expect("Should find vma");
//             assert_eq!(found1.backing, backing_value);

//             let found1_anon_vma =
//                 anon_area.find_mapping(&faulting_address1);
//             assert_eq!(
//                 found1_anon_vma.unwrap().frame.start_address(),
//                 frame1.start_address()
//             );
//         })
//     }

//     /// Tests the same thing as above, but with two different frames
//     #[test_case]
//     fn test_mm_anon_vm_backing2() {
//         let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm = Mm::new(pml4_frame);

//         // anon vm area to serve as backing for all vmas
//         let anon_area = Arc::new(AnonVmArea::new());
//         let backing_value = Arc::as_ptr(&anon_area) as u64;

//         let frame1 = alloc_frame().expect("Could not allocate PhysFrame");
//         let frame2 = alloc_frame().expect("Could not allocate PhysFrame");

//         mm.with_vma_tree_mutable(|tree| {
//             let vm_area = mm.insert_vma(tree, 0, 0x2000, backing_value, VmAreaFlags::READ | VmAreaFlags::WRITE, true);

//             // faulting_addresses and rounded down versions
//             let faulting_address1: u64 = 0x500;
//             let faulting_address2: u64 = 0x1500;

//             let faulting_address1_round = (faulting_address1 - vm_area.start) & !(PAGE_SIZE as u64 - 1);
//             let faulting_address2_round = (faulting_address2 - vm_area.start) & !(PAGE_SIZE as u64 - 1);

//             // maps the vm_area and offset to the frame
//             let chain1 = Arc::new(AnonVmaChain {
//                 offset: faulting_address1_round,
//                 frame: frame1.into(),
//             });

//             // maps the vm_area and offset to the frame
//             let chain2 = Arc::new(AnonVmaChain {
//                 offset: faulting_address2_round,
//                 frame: frame2.into(),
//             });

//             anon_area.insert_mapping(chain1.clone());
//             anon_area.insert_mapping(chain2.clone());

//             anon_area.print_mappings();

//             // get the vma from some address access (as we would in pf handler)
//             let found = mm.find_vma(faulting_address1, tree).expect("Should find vma");
//             assert_eq!(found.backing, backing_value);

//             let found1_anon_vma = anon_area.find_mapping(faulting_address1_round);

//             assert_eq!(
//                 found1_anon_vma.unwrap().frame.start_address(),
//                 frame1.start_address()
//             );

//             // get the vma from some address access (as we would in pf handler)
//             assert_eq!(found.backing, backing_value);

//             let found2_anon_vma = anon_area.find_mapping(faulting_address2_round);

//             assert_eq!(
//                 found2_anon_vma.unwrap().frame.start_address(),
//                 frame2.start_address()
//             );
//         })
//     }

//     /// Simulates multiple processes sharing memory by mapping multiple
//     /// VMAs to the same anon_vma
//     #[test_case]
//     fn test_mm_multiple_vmas() {
//         let pml4_frame1 = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm1 = Mm::new(pml4_frame1);

//         let pml4_frame2 = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm2 = Mm::new(pml4_frame2);

//         let anon_area = Arc::new(AnonVmArea::new());
//         let backing_value = Arc::as_ptr(&anon_area) as u64;

//         // two different vmas with the same backing
//         // note: different start and end, so different faulting_addresses
//         // correspond to same anon_vma
//         mm1.with_vma_tree_mut(|tree_1| {
//             let vm_area1 = mm1.insert_vma(0, 0x1000, backing_value, VmAreaFlags::READ | VmAreaFlags::WRITE, true, tree_1);
//         });
//         mm2.with_vma_tree_mutable(|tree_2| {
//             let vm_area2 = mm2.insert_vma(0x1000, 0x2000, backing_value, VmAreaFlags::READ | VmAreaFlags::WRITE, true, tree_2);
//         });

//         // fault here and map a frame (later done lazily, for now we just allocate a frame)
//         let faulting_address1: u64 = 0x500;
//         let faulting_address1_round =
//             (faulting_address1 - vm_area1.start) & !(PAGE_SIZE as u64 - 1);

//         let faulting_address2: u64 = 0x1500;
//         let faulting_address2_round =
//             (faulting_address2 - vm_area2.start) & !(PAGE_SIZE as u64 - 1);

//         let frame = alloc_frame().expect("Could not get frame");

//         // NOTE: This is why i think the VMA field is not necessary, but idk
//         // maps the vm_area and offset to the frame
//         let chain1 = Arc::new(AnonVmaChain {
//             offset: faulting_address1_round,
//             frame: frame.into(),
//         });

//         anon_area.insert_mapping(chain1.clone());

//         // get the vma from some address access (as we would in pf handler)
//         mm1.with_vma_tree_(|tree_1| {
//             let found1 = mm1.find_vma(faulting_address1, tree_1).expect("Should find vma");
//         });
//         mm2.with_vma_tree(|tree_2| {
//             let found2 = mm2.find_vma(faulting_address2, tree_2).expect("Should find vma");
//         });
//         assert_eq!(found1.backing, found2.backing);

//         let found2_anon_vma =
//             anon_area.find_mapping(faulting_address2_round);

//         assert_eq!(
//             found1_anon_vma.unwrap().frame.start_address(),
//             found2_anon_vma.unwrap().frame.start_address()
//         );
//     }

//     #[test_case]
//     fn test_coalesce_left() {
//         let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm = Mm::new(pml4_frame);
//         mm.with_vma_tree_mutable(|tree| {
//             let vma1 = mm.insert_vma(0, 0x1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true, tree);
//             let got_vma1 = mm.find_vma(0x500,tree_2);

//             let vma2 = mm.insert_vma(0x1000, 0x2000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true, tree);
//             let got_vma1_new = mm.find_vma(0x500, tree);

//             assert_eq!(got_vma1.unwrap().start, mm.find_vma(0x1500, tree).unwrap().start);
//         });
//     }

//     #[test_case]
//     fn test_coalesce_right() {
//         let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm = Mm::new(pml4_frame);
//         mm.with_vma_tree(|tree| {
//         let vma1 = mm.insert_vma(&mut tree, 0x1000, 0x2000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true);
//         let vma2 = mm.insert_vma(&mut tree, 0x0, 0x1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true);
//         });
//         assert_eq!(0, mm.find_vma(0x1500, &mut tree).unwrap().start);
//     }

//     #[test_case]
//     fn test_coalesce_both() {
//         let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
//         let mm = Mm::new(pml4_frame);
//         mm.with_vma_tree(|tree| {
//         let vma1 = mm.insert_vma(&mut tree, 0x0, 0x1000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true);
//         let got_vma1 = mm.find_vma(0x500, &mut tree).unwrap();

//         let vma2 = mm.insert_vma(&mut tree, 0x2000, 0x3000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true);
//         let vma3 = mm.insert_vma(&mut tree, 0x1000, 0x2000, 0, VmAreaFlags::READ | VmAreaFlags::WRITE, true);
//         let got_vma2 = mm.find_vma(0x1500, &mut tree).unwrap();
//         let got_vma3 = mm.find_vma(0x2500, &mut tree).unwrap();
//     });
//         assert_eq!(got_vma1.start, got_vma2.start);
//         assert_eq!(got_vma2.start, got_vma3.start);
//     }
// }
