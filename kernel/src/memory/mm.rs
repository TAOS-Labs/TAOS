use crate::{constants::memory::PAGE_SIZE, serial_println};
use alloc::{collections::btree_map::BTreeMap, sync::Arc, vec::Vec};
use bitflags::bitflags;
use core::{any::Any, fmt::Debug};
use spin::Mutex;
use x86_64::{
    structures::paging::{Mapper, Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

use super::paging::remove_mapping;

type VmaTree = BTreeMap<usize, Arc<Mutex<VmArea>>>;

/// The overall memory management structure.
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
        tree: &mut VmaTree,
        start: u64,
        end: u64,
        initial_backing: Arc<dyn VmAreaBacking>,
        flags: VmAreaFlags,
    ) -> Arc<Mutex<VmArea>> {
        let new_vma = Arc::new(Mutex::new(VmArea::new(
            start,
            end,
            initial_backing.clone(),
            flags,
        )));
        // Insert the new VMA into the backing's list.
        initial_backing.insert_vma(new_vma.clone());
        // For now, we do not perform any coalescing.
        tree.insert(start as usize, new_vma.clone());
        new_vma
    }

    /// Insert a copied VmArea into the VMA tree.
    ///
    /// Unlike `insert_vma` (which creates a single segment covering the entire region),
    /// this function takes in a segments map to support multiple backing segments.
    pub fn insert_copied_vma(
        tree: &mut VmaTree,
        start: u64,
        end: u64,
        segments: BTreeMap<u64, VmAreaSegment>,
        flags: VmAreaFlags,
    ) -> Arc<Mutex<VmArea>> {
        let new_vma = Arc::new(Mutex::new(VmArea::new_copied(start, end, segments, flags)));
        {
            // For each segment, insert the new VMA into the backing's list.
            let locked = new_vma.lock();
            for seg in locked.segments.values() {
                seg.backing.insert_vma(new_vma.clone());
            }
        }
        tree.insert(start as usize, new_vma.clone());
        new_vma
    }

    /// Stub: coalescing is not handled now.
    pub fn coalesce_vma_left(
        candidate: Arc<Mutex<VmArea>>,
        _tree: &mut VmaTree,
    ) -> Arc<Mutex<VmArea>> {
        candidate
    }

    /// Stub: coalescing is not handled now.
    pub fn coalesce_vma_right(
        candidate: Arc<Mutex<VmArea>>,
        _tree: &mut VmaTree,
    ) -> Arc<Mutex<VmArea>> {
        candidate
    }

    /// Remove the VmArea starting at the given address.
    pub fn remove_vma(start: u64, tree: &mut VmaTree) -> Option<(usize, Arc<Mutex<VmArea>>)> {
        tree.remove_entry(&(start as usize))
    }

    /// Shrink a VMA.
    ///
    /// This updates the VMA and its (single) segment’s reverse mappings.
    /// (Note: In the multiple-backings approach the reverse mapping lookup is per backing.)
    pub fn shrink_vma(
        old_start: u64,
        new_start: u64,
        new_end: u64,
        mapper: &mut impl Mapper<Size4KiB>,
        tree: &mut VmaTree,
    ) -> Option<Arc<Mutex<VmArea>>> {
        let vma = Mm::remove_vma(old_start, tree).unwrap().1;
        {
            let mut vma_guard = vma.lock();

            // Remove all mappings for pages that are being dropped.
            for va in (old_start..new_start).step_by(PAGE_SIZE) {
                let page = Page::containing_address(VirtAddr::new(va));
                remove_mapping(page, mapper);
            }
            for va in (new_end..vma_guard.end).step_by(PAGE_SIZE) {
                let page = Page::containing_address(VirtAddr::new(va));
                remove_mapping(page, mapper);
            }

            // For now, we assume a single segment covering the VMA.
            if let Some((_seg_start, segment)) = vma_guard.segments.iter_mut().next() {
                let remove_diff = new_start - old_start;
                let bound = new_end - old_start;

                // Update the reverse mapping stored in the segment's backing.
                let mut mappings = segment.backing.mappings().lock();
                let mut updated_mappings: BTreeMap<u64, Arc<VmaChain>> = BTreeMap::new();

                for (&offset, chain) in mappings.iter() {
                    if offset < remove_diff {
                        continue;
                    }
                    if offset >= bound {
                        break;
                    }
                    let new_offset = offset - remove_diff;
                    let updated_chain = Arc::new(VmaChain {
                        offset: new_offset,
                        frame: chain.frame.clone(),
                    });
                    updated_mappings.insert(new_offset, updated_chain);
                }
                *mappings = updated_mappings;

                // Update the segment to reflect the new size.
                // Since the VMA itself is shifting, we normalize the segment to start at 0.
                segment.start = 0;
                segment.end = new_end - new_start;
            }

            // Update the VMA boundaries.
            vma_guard.start = new_start;
            vma_guard.end = new_end;
        }

        tree.insert(new_start as usize, vma.clone());
        Mm::find_vma(new_start, tree)
    }

    /// Find a VmArea that contains the given virtual address.
    pub fn find_vma(addr: u64, tree: &VmaTree) -> Option<Arc<Mutex<VmArea>>> {
        // Look for the area with the largest start address <= addr.
        let candidate = tree.range(..=addr as usize).next_back();
        if let Some((_, vma)) = candidate {
            if addr < vma.lock().end {
                return Some(vma.clone());
            }
        }
        None
    }

    /// Debug fn to print VMAs.
    pub fn print_vma(tree: &VmaTree) {
        for (i, vma) in tree.iter().enumerate() {
            serial_println!("VMA {}: {:#?}", i, vma.1.lock());
        }
    }

    pub fn with_vma_tree_mutable<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut VmaTree) -> R,
    {
        let mut tree = self.vma_tree.lock();
        f(&mut tree)
    }

    pub fn with_vma_tree<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&VmaTree) -> R,
    {
        let tree = self.vma_tree.lock();
        f(&tree)
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct VmAreaFlags: u64 {
        const WRITABLE    = 1 << 0;
        const EXECUTE     = 1 << 1; // For code segments.
        const SHARED      = 1 << 2; // If 1, shared. If 0, private (COW).
        const GROWS_DOWN  = 1 << 3; // Stack.
        const LOCKED      = 1 << 4; // Not to be evicted by PRA.
        const MAPPED_FILE = 1 << 5; // Indicates a file backed mapping.
        const HUGEPAGE    = 1 << 6; // Indicates that this VMA could contain huge pages.
        const FIXED       = 1 << 7; // Mappings in the VMA won't be changed.
        const NORESERVE   = 1 << 8; // For lazy loading.
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

/// A VMA now stores multiple backing segments, each for a subrange.
#[derive(Clone, Debug)]
pub struct VmArea {
    pub start: u64,
    pub end: u64,
    /// Mapping from an offset (relative to `start`) to a segment.
    pub segments: BTreeMap<u64, VmAreaSegment>,
    pub flags: VmAreaFlags,
}

impl VmArea {
    /// Create a new VMA with a single backing segment covering the whole region.
    pub fn new(
        start: u64,
        end: u64,
        initial_backing: Arc<dyn VmAreaBacking>,
        flags: VmAreaFlags,
    ) -> Self {
        let mut segments = BTreeMap::new();
        // The segment covers the entire VMA: its offsets are relative to `start`.
        segments.insert(
            0,
            VmAreaSegment {
                start: 0,
                end: end - start,
                backing: initial_backing,
            },
        );
        VmArea {
            start,
            end,
            segments,
            flags,
        }
    }

    /// Create a new VmArea with a pre-populated segments map.
    ///
    /// This function is used when copying a VmArea (e.g. during fork) where
    /// there might be multiple backing segments.
    pub fn new_copied(
        start: u64,
        end: u64,
        segments: BTreeMap<u64, VmAreaSegment>,
        flags: VmAreaFlags,
    ) -> Self {
        VmArea {
            start,
            end,
            segments,
            flags,
        }
    }
}

/// A segment within a VmArea representing a subrange with its own backing.
#[derive(Clone, Debug)]
pub struct VmAreaSegment {
    /// Start offset relative to the VmArea's start.
    pub start: u64,
    /// End offset relative to the VmArea's start.
    pub end: u64,
    /// The backing for this segment.
    pub backing: Arc<dyn VmAreaBacking>,
}

/// A trait for all VM Area backing stores.
pub trait VmAreaBacking: Send + Sync + Debug + Any {
    fn as_any(&self) -> &dyn Any;

    /// Returns a reference to the reverse mappings.
    fn mappings(&self) -> &Mutex<BTreeMap<u64, Arc<VmaChain>>>;

    /// Returns a reference to the list of VMAs associated with this backing.
    fn vmas(&self) -> &Mutex<Vec<Arc<Mutex<VmArea>>>>;

    /// Insert a new VMA into the list.
    fn insert_vma(&self, vma: Arc<Mutex<VmArea>>) {
        self.vmas().lock().push(vma);
    }

    /// Remove a VMA from the list by index.
    fn remove_vma(&self, index: usize) {
        self.vmas().lock().swap_remove(index);
    }

    /// Insert a new reverse mapping entry.
    fn insert_mapping(&self, chain: Arc<VmaChain>) {
        let mut map = self.mappings().lock();
        map.insert(chain.offset, chain);
    }

    /// Remove and return the reverse mapping entry for the given offset.
    fn remove_mapping(&self, offset: u64) -> Option<Arc<VmaChain>> {
        let mut map = self.mappings().lock();
        map.remove(&offset)
    }

    /// Find a reverse mapping entry for the given offset.
    fn find_mapping(&self, offset: u64) -> Option<Arc<VmaChain>> {
        let map = self.mappings().lock();
        map.get(&offset).cloned()
    }
}

/// Reverse mapping chain entry linking an offset to a physical page.
#[derive(Debug)]
pub struct VmaChain {
    pub offset: u64,
    pub frame: Arc<PhysFrame>,
}

impl VmaChain {
    pub fn new(offset: u64, frame: Arc<PhysFrame>) -> Self {
        VmaChain { offset, frame }
    }
}

/// Anonymous VM area for managing reverse mappings for anonymous pages.
#[derive(Debug)]
pub struct AnonVmArea {
    /// Reverse mappings keyed by offset.
    pub mappings: Mutex<BTreeMap<u64, Arc<VmaChain>>>,
    pub vmas: Mutex<Vec<Arc<Mutex<VmArea>>>>,
}

impl AnonVmArea {
    /// Create a new AnonVmArea with an empty mapping.
    pub fn new() -> Self {
        AnonVmArea {
            mappings: Mutex::new(BTreeMap::new()),
            vmas: Mutex::new(Vec::new()),
        }
    }

    /// Debug function to print all page-to-frame mappings.
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

    pub fn insert_vma(&mut self, vma: Arc<Mutex<VmArea>>) {
        self.vmas.lock().push(vma);
    }

    pub fn remove_vma(&mut self, index: usize) {
        self.vmas.lock().swap_remove(index);
    }

    /// Insert a new reverse mapping entry.
    pub fn insert_mapping(&self, chain: Arc<VmaChain>) {
        let mut map = self.mappings.lock();
        map.insert(chain.offset, chain);
    }

    /// Remove and return the reverse mapping entry for the given offset.
    pub fn remove_mapping(&self, offset: u64) -> Option<Arc<VmaChain>> {
        let mut map = self.mappings.lock();
        map.remove(&offset)
    }

    /// Find a reverse mapping entry for the given offset.
    pub fn find_mapping(&self, offset: u64) -> Option<Arc<VmaChain>> {
        let map = self.mappings.lock();
        map.get(&offset).cloned()
    }
}

impl VmAreaBacking for AnonVmArea {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn mappings(&self) -> &Mutex<BTreeMap<u64, Arc<VmaChain>>> {
        &self.mappings
    }

    fn vmas(&self) -> &Mutex<Vec<Arc<Mutex<VmArea>>>> {
        &self.vmas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{sync::Arc, vec::Vec};
    use x86_64::{structures::paging::PhysFrame, PhysAddr};

    // (Import additional items from your crate as needed.)
    use crate::{
        constants::memory::PAGE_SIZE,
        memory::{
            frame_allocator::alloc_frame,
            paging::{create_mapping, remove_mapping},
            AnonVmArea, Mm, VmAreaFlags, VmaChain, KERNEL_MAPPER,
        },
    };

    /// Tests insertion and lookup of VM Areas in the memory manager.
    ///
    /// This test creates a memory manager (`Mm`) with a dummy PML4 frame and a new
    /// anonymous backing area (`AnonVmArea`). It inserts two VM Areas into the internal VMA tree:
    /// one covering addresses `[0, 500)` and another covering `[600, 1000)`. The test then
    /// verifies that looking up addresses 250 and 750 correctly returns the corresponding VM Areas
    /// with the expected starting addresses.
    #[test_case]
    async fn test_mm_vma_insert_find() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = Mm::insert_vma(tree, 0, 500, anon_area.clone(), VmAreaFlags::WRITABLE);
            let _vma2 = Mm::insert_vma(tree, 600, 1000, anon_area.clone(), VmAreaFlags::WRITABLE);
            // Test finding a VMA that covers a given address.
            let found1 = Mm::find_vma(250, tree);
            assert!(found1.is_some(), "Should find a VMA covering address 250");
            assert_eq!(found1.unwrap().lock().start, 0);

            let found2 = Mm::find_vma(750, tree);
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
    async fn test_mm_vma_remove() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            // Create a VmArea instance.
            let _vma = Mm::insert_vma(tree, 0, 500, anon_area.clone(), VmAreaFlags::WRITABLE);

            let found = Mm::find_vma(250, tree);
            assert_eq!(found.unwrap().lock().start, 0);

            // Remove the VMA starting at address 0.
            let removed = Mm::remove_vma(0, tree).unwrap();
            let removed_start = removed.1.lock().start;
            let found_after = Mm::find_vma(removed_start, tree);
            assert!(found_after.is_none());
        });
    }

    /// Verifies that an anonymous VM backing area correctly maps a faulted address to its corresponding frame.
    ///
    /// This test sets up a VM Area with an anonymous backing area and allocates a physical frame.
    /// It then simulates a fault at a specific address within the VM Area and maps that offset to the frame.
    /// The test checks that:
    /// - The VM Area can be correctly retrieved by its faulted address.
    /// - The backing pointer of the first segment matches the anonymous backing area.
    /// - The mapping in the anonymous area correctly returns the physical frame.
    #[test_case]
    async fn test_mm_anon_vm_backing() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area: Arc<dyn VmAreaBacking> = Arc::new(AnonVmArea::new());

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");

        let vm_area = mm.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(tree, 0, 0x1000, anon_area.clone(), VmAreaFlags::WRITABLE)
        });

        // Calculate the faulting address's aligned offset.
        let faulting_address1: u64 = 0x500;
        let vm_start = vm_area.lock().start;
        let faulting_address1_round = (faulting_address1 - vm_start) & !(PAGE_SIZE as u64 - 1);

        // Map the vm_area and offset to the frame.
        let chain1 = Arc::new(VmaChain {
            offset: faulting_address1_round,
            frame: frame1.into(),
        });
        anon_area.insert_mapping(chain1);

        mm.with_vma_tree(|tree| {
            let found1 = Mm::find_vma(faulting_address1, tree).expect("Should find vma");
            let found_vma = found1.lock();
            // Check backing pointer via the first segment.
            let seg = found_vma.segments.get(&0).expect("Segment missing");
            assert!(Arc::ptr_eq(&seg.backing, &anon_area));

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
    async fn test_mm_anon_vm_backing2() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area: Arc<dyn VmAreaBacking> = Arc::new(AnonVmArea::new());

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");
        let frame2 = alloc_frame().expect("Could not allocate PhysFrame");

        mm.with_vma_tree_mutable(|tree| {
            let vm_area = Mm::insert_vma(tree, 0, 0x2000, anon_area.clone(), VmAreaFlags::WRITABLE);

            let vm_start = vm_area.lock().start;
            let faulting_address1: u64 = 0x500;
            let faulting_address2: u64 = 0x1500;

            let faulting_address1_round = (faulting_address1 - vm_start) & !(PAGE_SIZE as u64 - 1);
            let faulting_address2_round = (faulting_address2 - vm_start) & !(PAGE_SIZE as u64 - 1);

            let chain1 = Arc::new(VmaChain {
                offset: faulting_address1_round,
                frame: frame1.into(),
            });
            let chain2 = Arc::new(VmaChain {
                offset: faulting_address2_round,
                frame: frame2.into(),
            });

            anon_area.insert_mapping(chain1);
            anon_area.insert_mapping(chain2);

            let found = Mm::find_vma(faulting_address1, tree).expect("Should find vma");
            let found_vma = found.lock();
            assert!(Arc::ptr_eq(
                &found_vma.segments.get(&0).unwrap().backing,
                &anon_area
            ));

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
    /// - The backing pointer in both VM Areas (accessed via their first segment) is the same.
    /// - The anonymous mapping returns the same frame for the corresponding offset.
    #[test_case]
    async fn test_mm_multiple_vmas() {
        let pml4_frame1 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm1 = Mm::new(pml4_frame1);
        let pml4_frame2 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm2 = Mm::new(pml4_frame2);
        let anon_area = Arc::new(AnonVmArea::new());

        let vm_area1 = mm1.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(tree, 0, 0x1000, anon_area.clone(), VmAreaFlags::WRITABLE)
        });
        let vm_area2 = mm2.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
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
        let chain = Arc::new(VmaChain {
            offset: faulting_address1_round,
            frame: frame.into(),
        });
        anon_area.insert_mapping(chain);

        let found1 = mm1
            .with_vma_tree(|tree| Mm::find_vma(faulting_address1, tree).expect("Should find vma"));
        let found2 = mm2
            .with_vma_tree(|tree| Mm::find_vma(faulting_address2, tree).expect("Should find vma"));
        let seg1 = found1.lock().segments.get(&0).unwrap().clone();
        let seg2 = found2.lock().segments.get(&0).unwrap().clone();
        assert!(Arc::ptr_eq(&seg1.backing, &seg2.backing));

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
    /// Since coalescing is not implemented yet (the functions are stubs), this test is ignored.
    // #[test_case]
    async fn test_coalesce_left() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = Mm::insert_vma(tree, 0, 0x1000, anon_area.clone(), VmAreaFlags::WRITABLE);
            let got_vma1 = Mm::find_vma(0x500, tree).expect("Should find vma");

            let _vma2 = Mm::insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
            );
            let v1_start = got_vma1.lock().start;
            let v2_start = Mm::find_vma(0x1500, tree)
                .expect("Should find vma")
                .lock()
                .start;
            // Expect coalescing, so both should have the same start.
            assert_eq!(v1_start, v2_start);
        });
    }

    /// Tests coalescing of adjacent VM Areas on the right.
    ///
    /// Since coalescing is not implemented yet, this test is marked as ignored.
    // #[test_case]
    async fn test_mm_coalesce_right() {
        // This test is marked ignored until coalescing is implemented.
    }

    /// Tests coalescing of adjacent VM Areas on both left and right sides.
    ///
    /// Since coalescing is not implemented yet, this test is marked as ignored.
    // #[test_case]
    async fn test_coalesce_both() {
        // This test is marked ignored until coalescing is implemented.
    }

    /// Tests shrinking a VMA from the left side.
    ///
    /// In this test, we create a VMA that spans three pages starting at 0x40000000.
    /// We populate its reverse mappings with one mapping per page.
    /// Then we shrink the VMA by removing the leftmost page, so that the new start is shifted
    /// by one page while the end remains unchanged.
    /// The test asserts that:
    /// - The new VMA covers only the right two pages.
    /// - The reverse mappings have been updated so that the surviving mappings are shifted.
    #[test_case]
    async fn test_shrink_vma_left() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());
        let old_start = 0x40000000;
        let old_end = old_start + 3 * PAGE_SIZE as u64;

        // Insert VMA and populate its reverse mappings.
        mm.with_vma_tree_mutable(|tree| {
            let vma = Mm::insert_vma(
                tree,
                old_start,
                old_end,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
            );
            {
                let locked_vma = vma.lock();
                let seg = locked_vma.segments.get(&0).expect("Segment missing");
                let mut mappings = seg.backing.mappings().lock();
                // For each page in the VMA, create a mapping.
                for i in 0..3 {
                    let offset = i as u64 * PAGE_SIZE as u64;
                    let va = old_start + offset;
                    let page = Page::containing_address(VirtAddr::new(va));
                    let mut mapper = KERNEL_MAPPER.lock();
                    let frame = create_mapping(
                        page,
                        &mut *mapper,
                        Some(PageTableFlags::PRESENT | PageTableFlags::WRITABLE),
                    );
                    mappings.insert(
                        offset,
                        Arc::new(VmaChain {
                            offset,
                            frame: Arc::new(frame),
                        }),
                    );
                }
            }
        });

        let new_start = old_start + PAGE_SIZE as u64;
        let new_end = old_end;
        let shrunk = mm.with_vma_tree_mutable(|tree| {
            let mut mapper = KERNEL_MAPPER.lock();
            Mm::shrink_vma(old_start, new_start, new_end, &mut *mapper, tree)
        });
        assert!(shrunk.is_some());
        let vma = shrunk.unwrap();
        let locked = vma.lock();
        assert_eq!(locked.start, new_start);
        assert_eq!(locked.end, new_end);
        let seg = locked.segments.get(&0).expect("Segment missing");
        let mappings = seg.backing.mappings().lock();
        assert_eq!(mappings.len(), 2);
        // The surviving offsets should have been shifted so that the leftmost surviving mapping is at offset 0.
        assert!(mappings.contains_key(&0));
        assert!(mappings.contains_key(&(PAGE_SIZE as u64)));
    }

    /// Tests shrinking a VMA from the right side.
    ///
    /// In this test, a VMA spanning three pages is created.
    /// Its reverse mappings are populated with one mapping per page.
    /// We then shrink the VMA by removing the rightmost page while keeping the start unchanged.
    /// The test asserts that:
    /// - The resulting VMA covers the left two pages.
    /// - The reverse mappings remain unshifted.
    #[test_case]
    async fn test_shrink_vma_right() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());
        let old_start = 0x50000000;
        let old_end = old_start + 3 * PAGE_SIZE as u64;

        mm.with_vma_tree_mutable(|tree| {
            let vma = Mm::insert_vma(
                tree,
                old_start,
                old_end,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
            );
            {
                let locked_vma = vma.lock();
                let seg = locked_vma.segments.get(&0).expect("Segment missing");
                let mut mappings = seg.backing.mappings().lock();
                for i in 0..3 {
                    let offset = i as u64 * PAGE_SIZE as u64;
                    let va = old_start + offset;
                    let page = x86_64::structures::paging::Page::containing_address(
                        x86_64::VirtAddr::new(va),
                    );
                    let mut mapper = KERNEL_MAPPER.lock();
                    let frame = create_mapping(
                        page,
                        &mut *mapper,
                        Some(
                            x86_64::structures::paging::PageTableFlags::WRITABLE
                                | x86_64::structures::paging::PageTableFlags::PRESENT,
                        ),
                    );
                    mappings.insert(
                        offset,
                        Arc::new(VmaChain {
                            offset,
                            frame: Arc::new(frame),
                        }),
                    );
                }
            }
        });

        // Shrink right: keep the left two pages.
        let new_start = old_start;
        let new_end = old_end - PAGE_SIZE as u64;
        let shrunk = mm.with_vma_tree_mutable(|tree| {
            let mut mapper = KERNEL_MAPPER.lock();
            Mm::shrink_vma(old_start, new_start, new_end, &mut *mapper, tree)
        });
        assert!(shrunk.is_some());
        let vma = shrunk.unwrap();
        let locked = vma.lock();
        assert_eq!(locked.start, new_start);
        assert_eq!(locked.end, new_end);
        let seg = locked.segments.get(&0).expect("Segment missing");
        let mappings = seg.backing.mappings().lock();
        // Two mappings should remain.
        assert_eq!(mappings.len(), 2);
        assert!(mappings.contains_key(&0));
        assert!(mappings.contains_key(&(PAGE_SIZE as u64)));
    }

    /// Tests shrinking a VMA from both the left and right sides simultaneously.
    ///
    /// In this test, a VMA covering four pages is created and populated with reverse mappings for each page.
    /// We then shrink the VMA by removing one page from the left and one page from the right, so that the surviving
    /// region covers the two middle pages.
    /// The test asserts that:
    /// - The new VMA boundaries are updated.
    /// - The reverse mappings are updated so that the surviving pages have their offsets shifted.
    #[test_case]
    async fn test_shrink_vma_both() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());
        let old_start = 0x60000000;
        let old_end = old_start + 4 * PAGE_SIZE as u64;

        mm.with_vma_tree_mutable(|tree| {
            let vma = Mm::insert_vma(
                tree,
                old_start,
                old_end,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
            );
            {
                let locked_vma = vma.lock();
                let seg = locked_vma.segments.get(&0).expect("Segment missing");
                let mut mappings = seg.backing.mappings().lock();
                for i in 0..4 {
                    let offset = i as u64 * PAGE_SIZE as u64;
                    let va = old_start + offset;
                    let page = x86_64::structures::paging::Page::containing_address(
                        x86_64::VirtAddr::new(va),
                    );
                    let mut mapper = KERNEL_MAPPER.lock();
                    let frame = create_mapping(
                        page,
                        &mut *mapper,
                        Some(
                            x86_64::structures::paging::PageTableFlags::WRITABLE
                                | x86_64::structures::paging::PageTableFlags::PRESENT,
                        ),
                    );
                    mappings.insert(
                        offset,
                        Arc::new(VmaChain {
                            offset,
                            frame: Arc::new(frame),
                        }),
                    );
                }
            }
        });

        // Shrink both sides: remove the leftmost and rightmost pages.
        let new_start = old_start + PAGE_SIZE as u64;
        let new_end = old_end - PAGE_SIZE as u64;
        let shrunk = mm.with_vma_tree_mutable(|tree| {
            let mut mapper = KERNEL_MAPPER.lock();
            Mm::shrink_vma(old_start, new_start, new_end, &mut *mapper, tree)
        });
        assert!(shrunk.is_some());

        let vma = shrunk.unwrap();
        let locked = vma.lock();
        assert_eq!(locked.start, new_start);
        assert_eq!(locked.end, new_end);

        let seg = locked.segments.get(&0).expect("Segment missing");
        let mappings = seg.backing.mappings().lock();
        // After shrink, expect two mappings.
        assert_eq!(mappings.len(), 2);
        assert!(mappings.contains_key(&0));
        assert!(mappings.contains_key(&(PAGE_SIZE as u64)));
    }

    /// Tests shrinking a VMA completely so that no pages survive.
    ///
    /// In this test, a VMA covering two pages is created and populated with reverse mappings for each page.
    /// We then shrink the VMA so that new_start equals new_end, meaning that the entire VMA is unmapped.
    /// This is similar to munmap().
    #[test_case]
    async fn test_shrink_vma_whole() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());
        let old_start = 0x70000000;
        let old_end = old_start + 2 * PAGE_SIZE as u64;

        mm.with_vma_tree_mutable(|tree| {
            let vma = Mm::insert_vma(
                tree,
                old_start,
                old_end,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
            );
            {
                let locked_vma = vma.lock();
                let seg = locked_vma.segments.get(&0).expect("Segment missing");
                let mut mappings = seg.backing.mappings().lock();
                for i in 0..2 {
                    let offset = i as u64 * PAGE_SIZE as u64;
                    let va = old_start + offset;
                    let page = Page::containing_address(VirtAddr::new(va));
                    let mut mapper = KERNEL_MAPPER.lock();
                    let frame = create_mapping(
                        page,
                        &mut *mapper,
                        Some(PageTableFlags::WRITABLE | PageTableFlags::PRESENT),
                    );
                    mappings.insert(
                        offset,
                        Arc::new(VmaChain {
                            offset,
                            frame: Arc::new(frame),
                        }),
                    );
                }
            }
        });

        // Shrink whole: new_start == new_end, so no pages remain.
        let new_boundary = old_start + PAGE_SIZE as u64;
        let shrunk = mm.with_vma_tree_mutable(|tree| {
            let mut mapper = KERNEL_MAPPER.lock();
            Mm::shrink_vma(old_start, new_boundary, new_boundary, &mut *mapper, tree)
        });
        // When the entire VMA is shrunk away, shrink_vma returns None.
        assert!(shrunk.is_none());
    }
}
