use crate::serial_println;
use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use bitflags::bitflags;
use spin::Mutex;
use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};

type VmaTree = BTreeMap<usize, Arc<Mutex<VmArea>>>;

#[derive(Debug)]
pub struct Mm {
    pub vma_tree: Mutex<VmaTree>,
    pub pml4_frame: PhysFrame<Size4KiB>,
}

impl Clone for Mm {
    fn clone(&self) -> Self {
        let new_tree: VmaTree = self.with_vma_tree(|tree| {
            tree.iter()
                .map(|(&k, v)| {
                    let new_vma = {
                        let guard = v.lock();
                        guard.clone()
                    };
                    (k, Arc::new(Mutex::new(new_vma)))
                })
                .collect()
        });
        Mm {
            vma_tree: Mutex::new(new_tree),
            pml4_frame: self.pml4_frame,
        }
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
        const WRITABLE = 0b001;
        const EXECUTE = 0b10; // For code segments
        const SHARED = 0b100; // If 1, shared. If 0, private (COW)
        const GROWS_DOWN = 0b1000; // Stack
        const PINNED = 0b1_0000; // Not to be evicted by PRA
        const MAPPED_FILE = 0b10_0000; // Indicates a file backed mapping
        const HUGEPAGE = 0b100_0000; // Indicates that this VMA could contain huge pages
        const FIXED = 0b1000_0000; // Mappings in the VMA wont be changed
        const NORESERVE = 0b1_0000_0000; // For lazy loading
    }
}

pub fn vma_to_page_flags(vma_flags: VmAreaFlags) -> PageTableFlags {
    let mut flags = PageTableFlags::USER_ACCESSIBLE;

    if vma_flags.contains(VmAreaFlags::WRITABLE) {
        flags.set(PageTableFlags::WRITABLE, true);
    }
    if vma_flags.contains(VmAreaFlags::EXECUTE) {
        flags.set(PageTableFlags::NO_EXECUTE, false);
    }

    flags
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

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use x86_64::{structures::paging::PhysFrame, PhysAddr};

    // (Import additional items from your crate as needed.)
    use crate::{constants::memory::PAGE_SIZE, memory::frame_allocator::alloc_frame};

    use super::*;

    /// Tests insertion and lookup of VM Areas in the memory manager.
    ///
    /// This test creates a memory manager (`Mm`) with a dummy PML4 frame and a new
    /// anonymous backing area (`AnonVmArea`). It inserts two VM Areas into the internal VMA tree:
    /// one covering addresses `[0, 500)` and another covering `[600, 1000)`. The test then
    /// verifies that looking up addresses 250 and 750 correctly returns the corresponding VM Areas
    /// with the expected starting addresses.
    #[test_case]
    fn test_mm_vma_insert_find() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = mm.insert_vma(tree, 0, 500, anon_area.clone(), VmAreaFlags::WRITABLE, true);
            let _vma2 = mm.insert_vma(
                tree,
                600,
                1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            // Test finding a VMA that covers a given address.
            let found1 = mm.find_vma(250, tree);
            assert!(found1.is_some(), "Should find a VMA covering address 250");
            assert_eq!(found1.unwrap().lock().start, 0);

            let found2 = mm.find_vma(750, tree);
            assert!(found2.is_some(), "Should find a VMA covering address 750");
            assert_eq!(found2.unwrap().lock().start, 600);
        });
    }

    /// Tests removal of a VM Area from the memory manager's VMA tree.
    ///
    /// This test creates a memory manager with a dummy PML4 frame and a new anonymous backing area.
    /// It inserts a single VM Area spanning `[0, 500)` and verifies that it can be found by address lookup.
    /// The test then removes the VM Area starting at address 0 and confirms that subsequent lookup fails,
    /// ensuring that removal works correctly.
    #[test_case]
    fn test_mm_vma_remove() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            // Create a VmArea instance.
            let _vma = mm.insert_vma(tree, 0, 500, anon_area.clone(), VmAreaFlags::WRITABLE, true);

            let found = mm.find_vma(250, tree);
            assert_eq!(found.unwrap().lock().start, 0);

            // Remove the VMA starting at address 0.
            let removed = mm.remove_vma(0, tree).unwrap();
            let removed_start = removed.lock().start;
            let found_after = mm.find_vma(removed_start, tree);
            assert!(found_after.is_none());
        });
    }

    /// Verifies that an anonymous VM backing area correctly maps a faulted address to its corresponding frame.
    ///
    /// This test sets up a VM Area with an anonymous backing area and allocates a physical frame.
    /// It then simulates a fault at a specific address within the VM Area and maps that offset to the frame.
    /// The test checks that:
    /// - The VM Area can be correctly retrieved by its faulted address.
    /// - The backing pointer of the VM Area matches the anonymous backing area.
    /// - The mapping in the anonymous area correctly returns the physical frame.
    #[test_case]
    fn test_mm_anon_vm_backing() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");

        let vm_area = mm.with_vma_tree_mutable(|tree| {
            mm.insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            )
        });

        // Calculate the faulting address's aligned offset.
        let faulting_address1: u64 = 0x500;
        let vm_start = vm_area.lock().start;
        let faulting_address1_round = (faulting_address1 - vm_start) & !(PAGE_SIZE as u64 - 1);

        // Map the vm_area and offset to the frame.
        let chain1 = Arc::new(AnonVmaChain {
            offset: faulting_address1_round,
            frame: frame1.into(),
        });
        anon_area.insert_mapping(chain1);

        mm.with_vma_tree(|tree| {
            let found1 = mm
                .find_vma(faulting_address1, tree)
                .expect("Should find vma");
            // Compare backing using pointer equality.
            assert!(Arc::ptr_eq(&found1.lock().backing, &anon_area));

            let found1_anon = anon_area
                .find_mapping(faulting_address1_round)
                .expect("Mapping not found");
            assert_eq!(found1_anon.frame.start_address(), frame1.start_address());
        });
    }

    /// Verifies that an anonymous VM backing area correctly handles multiple frame mappings.
    ///
    /// This test sets up a VM Area spanning `[0, 0x2000)` with an anonymous backing area and allocates two distinct frames.
    /// It simulates faults at two different addresses within the VM Area and maps each offset to a different frame.
    /// The test asserts that the correct physical frame is returned for each fault offset.
    #[test_case]
    fn test_mm_anon_vm_backing2() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");
        let frame2 = alloc_frame().expect("Could not allocate PhysFrame");

        mm.with_vma_tree_mutable(|tree| {
            let vm_area = mm.insert_vma(
                tree,
                0,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );

            let vm_start = vm_area.lock().start;
            let faulting_address1: u64 = 0x500;
            let faulting_address2: u64 = 0x1500;

            let faulting_address1_round = (faulting_address1 - vm_start) & !(PAGE_SIZE as u64 - 1);
            let faulting_address2_round = (faulting_address2 - vm_start) & !(PAGE_SIZE as u64 - 1);

            let chain1 = Arc::new(AnonVmaChain {
                offset: faulting_address1_round,
                frame: frame1.into(),
            });
            let chain2 = Arc::new(AnonVmaChain {
                offset: faulting_address2_round,
                frame: frame2.into(),
            });

            anon_area.insert_mapping(chain1);
            anon_area.insert_mapping(chain2);

            let found = mm
                .find_vma(faulting_address1, tree)
                .expect("Should find vma");
            assert!(Arc::ptr_eq(&found.lock().backing, &anon_area));

            let found1_anon = anon_area
                .find_mapping(faulting_address1_round)
                .expect("Mapping not found");
            assert_eq!(found1_anon.frame.start_address(), frame1.start_address());

            let found2_anon = anon_area
                .find_mapping(faulting_address2_round)
                .expect("Mapping not found");
            assert_eq!(found2_anon.frame.start_address(), frame2.start_address());
        });
    }

    /// Simulates multiple processes sharing memory by mapping different VM Areas to the same anonymous backing.
    ///
    /// This test creates two memory manager instances (`mm1` and `mm2`), each with its own VMA tree.
    /// Two VM Areas are inserted with non-overlapping ranges but sharing the same anonymous backing area.
    /// A single physical frame is mapped to a faulting offset which should be consistent across both VM Areas.
    /// The test verifies that:
    /// - The backing pointer in both VM Areas is the same.
    /// - The anonymous mapping returns the same frame for the corresponding offset.
    #[test_case]
    fn test_mm_multiple_vmas() {
        let pml4_frame1 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm1 = Mm::new(pml4_frame1);
        let pml4_frame2 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm2 = Mm::new(pml4_frame2);
        let anon_area = Arc::new(AnonVmArea::new());

        let vm_area1 = mm1.with_vma_tree_mutable(|tree| {
            mm1.insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            )
        });
        let vm_area2 = mm2.with_vma_tree_mutable(|tree| {
            mm2.insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            )
        });

        let faulting_address1: u64 = 0x500;
        let faulting_address2: u64 = 0x1500;

        let vm1_start = vm_area1.lock().start;
        let vm2_start = vm_area2.lock().start;
        let faulting_address1_round = (faulting_address1 - vm1_start) & !(PAGE_SIZE as u64 - 1);
        let faulting_address2_round = (faulting_address2 - vm2_start) & !(PAGE_SIZE as u64 - 1);

        // Note: Both faulting offsets should be the same.
        let frame = alloc_frame().expect("Could not get frame");
        let chain = Arc::new(AnonVmaChain {
            offset: faulting_address1_round,
            frame: frame.into(),
        });
        anon_area.insert_mapping(chain);

        let found1 = mm1.with_vma_tree(|tree| {
            mm1.find_vma(faulting_address1, tree)
                .expect("Should find vma")
        });
        let found2 = mm2.with_vma_tree(|tree| {
            mm2.find_vma(faulting_address2, tree)
                .expect("Should find vma")
        });
        assert!(Arc::ptr_eq(&found1.lock().backing, &found2.lock().backing));

        let found1_anon = anon_area
            .find_mapping(faulting_address1_round)
            .expect("Mapping not found");
        let found2_anon = anon_area
            .find_mapping(faulting_address2_round)
            .expect("Mapping not found");
        assert_eq!(
            found1_anon.frame.start_address(),
            found2_anon.frame.start_address()
        );
    }

    /// Tests coalescing of adjacent VM Areas on the left.
    ///
    /// This test creates a VM Area covering `[0, 0x1000)` and then inserts a second VM Area starting
    /// exactly at `0x1000` and ending at `0x2000`. The test verifies that the two adjacent VM Areas are
    /// coalesced into a single VM Area by checking that a lookup for an address in the first region returns
    /// a VM Area with the same start as the coalesced result.
    #[test_case]
    fn test_coalesce_left() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = mm.insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let got_vma1 = mm.find_vma(0x500, tree).expect("Should find vma");

            let _vma2 = mm.insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let v1_start = got_vma1.lock().start;
            let v2_start = mm
                .find_vma(0x1500, tree)
                .expect("Should find vma")
                .lock()
                .start;
            assert_eq!(v1_start, v2_start);
        });
    }

    /// Tests coalescing of adjacent VM Areas on the right.
    ///
    /// This test inserts two VM Areas: one covering `[0x1000, 0x2000)` and another covering `[0, 0x1000)`.
    /// Since the VM Area starting at `0` ends exactly where the first begins, they should be coalesced.
    /// A lookup of an address in the first region (e.g. `0x1500`) should return a VM Area starting at `0`.
    #[test_case]
    fn test_coalesce_right() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = mm.insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let _vma2 = mm.insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
        });
        let found = mm.with_vma_tree(|tree| mm.find_vma(0x1500, tree).expect("Should find vma"));
        assert_eq!(0, found.lock().start);
    }

    /// Tests coalescing of adjacent VM Areas on both left and right sides.
    ///
    /// This test inserts three VM Areas:
    /// - The first covering `[0, 0x1000)`,
    /// - The second covering `[0x2000, 0x3000)`,
    /// - The third covering `[0x1000, 0x2000)`.
    ///
    /// When the third VM Area is inserted, it should coalesce with both the first and second,
    /// resulting in a single coalesced VM Area. The test verifies that the start address for all
    /// resulting VM Areas is the same.
    #[test_case]
    fn test_coalesce_both() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        let (got_vma1, got_vma2, got_vma3) = mm.with_vma_tree_mutable(|tree| {
            let _vma1 = mm.insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let got_vma1 = mm.find_vma(0x500, tree).expect("Should find vma");

            let _vma2 = mm.insert_vma(
                tree,
                0x2000,
                0x3000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let _vma3 = mm.insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let got_vma2 = mm.find_vma(0x1500, tree).expect("Should find vma");
            let got_vma3 = mm.find_vma(0x2500, tree).expect("Should find vma");

            (got_vma1, got_vma2, got_vma3)
        });
        let start1 = got_vma1.lock().start;
        let start2 = got_vma2.lock().start;
        let start3 = got_vma3.lock().start;
        assert_eq!(start1, start2);
        assert_eq!(start2, start3);
    }
}
