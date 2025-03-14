use core::{any::Any, fmt::Debug};

use crate::{constants::memory::PAGE_SIZE, serial_println};
use alloc::{
    collections::{btree_map::BTreeMap, linked_list::LinkedList},
    sync::Arc,
    vec::Vec,
};
use bitflags::bitflags;
use spin::Mutex;
use x86_64::{
    structures::paging::{Mapper, Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

use super::paging::remove_mapping;

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

    /// Insert a new VmArea into the VMA tree, then coalesce it with adjacent regions if possible.
    pub fn insert_vma(
        tree: &mut VmaTree,
        start: u64,
        end: u64,
        backing: Arc<dyn VmAreaBacking>,
        flags: VmAreaFlags,
        anon: bool,
    ) -> Arc<Mutex<VmArea>> {
        // Initially create and insert the new VMA.
        let new_vma = Arc::new(Mutex::new(VmArea::new(start, end, backing, flags, anon, 0)));
        tree.insert(start as usize, new_vma.clone());
        // Call the coalesce helper.
        Self::coalesce_vma(new_vma, tree)
    }
    /// Attempts to coalesce the candidate VMA with its left and right neighbors.
    /// Returns the resulting (possibly merged) VMA. (Recursive portion omitted for brevity.)
    fn coalesce_vma(candidate: Arc<Mutex<VmArea>>, tree: &mut VmaTree) -> Arc<Mutex<VmArea>> {
        let mut merged = candidate;
        let mut did_merge = false;

        // Extract candidate fields once.
        let (cand_start, cand_end, cand_flags, cand_anon, cand_backing, cand_pgoff) = {
            let guard = merged.lock();
            (
                guard.start,
                guard.end,
                guard.flags,
                guard.anon,
                guard.backing.clone(),
                guard.pg_offset,
            )
        };

        // Left merge:
        if cand_start > 0 {
            if let Some(left) = Mm::find_vma(cand_start - 1, tree) {
                let left_guard = left.lock();
                // Can merge left if:
                //  - Left flags match candidate flags.
                //  - Left VMA ends exactly where candidate starts.
                //  - And candidate.pg_offset == left.pg_offset + ((cand_start - left.start) / PAGE_SIZE)
                if left_guard.flags == cand_flags
                    && left_guard.end == cand_start
                    && cand_pgoff
                        == left_guard.pg_offset + ((cand_start - left_guard.start) / PAGE_SIZE as u64)
                    && left_guard.backing.as_any().type_id() == cand_backing.as_any().type_id()
                {
                    let new_start = left_guard.start;
                    let new_end = cand_end;
                    let diff_bytes = cand_start - new_start;
                    let diff_pages = diff_bytes / PAGE_SIZE as u64;
                    // Remove both left and candidate from the tree.
                    tree.remove(&(left_guard.start as usize));
                    tree.remove(&(cand_start as usize));
                    drop(left_guard);

                    // Create merged VMA.
                    // We adopt left's pg_offset, so the merged VMA’s pg_offset becomes left.pg_offset.
                    merged = Arc::new(Mutex::new(VmArea::new(
                        new_start,
                        new_end,
                        cand_backing.clone(),
                        cand_flags,
                        cand_anon,
                        cand_pgoff - diff_pages,
                    )));
                    tree.insert(new_start as usize, merged.clone());
                    did_merge = true;

                    // Update the backing's reverse mappings: shift keys belonging to the candidate portion.
                    {
                        let mut mappings = cand_backing.mappings().lock();
                        let keys: Vec<u64> = mappings.keys().cloned().collect();
                        // We assume keys for the candidate portion are those < ((cand_end - cand_start) / PAGE_SIZE).
                        for key in keys {
                            // If a key falls within the candidate portion, shift it upward by diff_pages.
                            if key < (cand_end - cand_start) / PAGE_SIZE as u64 {
                                if let Some(chain) = mappings.remove(&key) {
                                    let new_key = key + diff_pages;
                                    mappings.insert(new_key, chain);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Refresh candidate info after a possible left merge.
        let (cand_start, cand_end, cand_pgoff) = {
            let guard = merged.lock();
            (guard.start, guard.end, guard.pg_offset)
        };

        // Right merge:
        if let Some(right) = Mm::find_vma(cand_end, tree) {
            let right_guard = right.lock();
            // Right merge is allowed if:
            //  - The candidate's end equals the right's start.
            //  - Their flags match.
            //  - Their backing types are the same.
            //  - And the right VMA’s pg_offset equals candidate.pg_offset + ((right.start - candidate.start) / PAGE_SIZE)
            if right_guard.flags == cand_flags
                && right_guard.start == cand_end
                && right_guard.backing.as_any().type_id() == cand_backing.as_any().type_id()
                && right_guard.pg_offset
                    == cand_pgoff + ((right_guard.start - cand_start) / PAGE_SIZE as u64)
            {
                let new_start = cand_start;
                let new_end = right_guard.end;
                // Remove candidate and right VMA from tree.
                tree.remove(&(cand_start as usize));
                tree.remove(&(right_guard.start as usize));
                drop(right_guard);
                // For a right merge, candidate's pg_offset remains unchanged.
                merged = Arc::new(Mutex::new(VmArea::new(
                    new_start,
                    new_end,
                    cand_backing.clone(),
                    cand_flags,
                    cand_anon,
                    cand_pgoff,
                )));
                tree.insert(new_start as usize, merged.clone());
                did_merge = true;

            }
        }

        if did_merge {
            Self::coalesce_vma(merged, tree)
        } else {
            merged
        }
    }

    /// TODO Backing remove
    /// Remove the VmArea starting at the given address.
    pub fn remove_vma(start: u64, tree: &mut VmaTree) -> Option<(usize, Arc<Mutex<VmArea>>)> {
        tree.remove_entry(&(start as usize))
    }

    /// Everything is page aligned
    pub fn shrink_vma(
        old_start: u64,
        new_start: u64,
        new_end: u64,
        mapper: &mut impl Mapper<Size4KiB>,
        tree: &mut VmaTree,
    ) -> Option<Arc<Mutex<VmArea>>> {
        let vma = Mm::remove_vma(old_start, tree).unwrap().1;
        {
            let vma = vma.lock();

            // remove all mappings from the shrink
            for va in (old_start..new_start).step_by(PAGE_SIZE) {
                let page = Page::containing_address(VirtAddr::new(va));
                remove_mapping(page, mapper);
            }
            for va in (new_end..vma.end).step_by(PAGE_SIZE) {
                let page = Page::containing_address(VirtAddr::new(va));
                remove_mapping(page, mapper);
            }

            // update AnonVma mappings
            let mut mappings = vma.backing.mappings().lock();
            let mut updated_anon_vma: BTreeMap<u64, Arc<VmaChain>> = BTreeMap::new();

            let remove_diff = new_start - old_start;
            let bound = new_end - old_start;

            // go through all offsets; if offset is mapping,
            for (&offset, chain) in mappings.iter_mut() {
                // don't start until we get to a mapping that we
                // actually care about
                if offset < remove_diff {
                    continue;
                }

                // if we exceed the right bound, no reason to continue
                if offset >= bound {
                    break;
                }

                let new_offset = offset - remove_diff;
                let updated_chain = Arc::new(VmaChain {
                    offset: new_offset,
                    frame: chain.frame.clone(),
                });

                updated_anon_vma.insert(new_offset, updated_chain);
            }

            *mappings = updated_anon_vma;
        }

        // if we shrunk this much, we removed the whole VMA
        if new_start == new_end {
            return None;
        }

        {
            let mut vma = vma.lock();
            vma.start = new_start;
            vma.end = new_end;
        }

        tree.insert(new_start as usize, vma.clone());
        return Mm::find_vma(new_start, tree);
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

    /// Debug fn to print vma
    pub fn print_vma(tree: &VmaTree) {
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
        const WRITABLE = 1 << 0;
        const EXECUTE = 1 << 1; // For code segments
        const SHARED = 1 << 2; // If 1, shared. If 0, private (COW)
        const GROWS_DOWN = 1 << 3; // Stack
        const LOCKED = 1 << 4; // Not to be evicted by PRA
        const MAPPED_FILE = 1 << 5; // Indicates a file backed mapping
        const HUGEPAGE = 1 << 6; // Indicates that this VMA could contain huge pages
        const FIXED = 1 << 7; // Mappings in the VMA wont be changed
        const NORESERVE = 1 << 8; // For lazy loading
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

/// A VMA describes a region of virtual memory in a process.
#[derive(Clone, Debug)]
pub struct VmArea {
    pub start: u64,
    pub end: u64,
    pub backing: Arc<dyn VmAreaBacking>,
    pub flags: VmAreaFlags,
    pub anon: bool,
    pub pg_offset: u64,
}

impl VmArea {
    pub fn new(
        start: u64,
        end: u64,
        backing: Arc<dyn VmAreaBacking>,
        flags: VmAreaFlags,
        anon: bool,
        pg_offset: u64,
    ) -> Self {
        let vma = VmArea {
            start,
            end,
            backing: backing.clone(),
            flags,
            anon,
            pg_offset,
        };

        // Insert a clone of the new VMA into the backing's VMA list.
        backing.insert_vma(Arc::new(Mutex::new(vma.clone())));
        vma
    }
}

/// A single trait for all VM Area backing stores.
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

    /// Remove and return the reverse mapping entry for the given VMA and offset.
    fn remove_mapping(&self, offset: u64) -> Option<Arc<VmaChain>> {
        let mut map = self.mappings().lock();
        map.remove(&offset)
    }

    /// Find a reverse mapping entry for the given VMA and offset.
    fn find_mapping(&self, offset: u64) -> Option<Arc<VmaChain>> {
        let map = self.mappings().lock();
        map.get(&offset).cloned()
    }
}

/// Reverse mapping chain entry that links a VMA and its offset to a physical page.
#[derive(Debug)]
pub struct VmaChain {
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

    /// Remove and return the reverse mapping entry for the given VMA and offset.
    pub fn remove_mapping(&self, offset: u64) -> Option<Arc<VmaChain>> {
        let mut map = self.mappings.lock();
        map.remove(&offset)
    }

    /// Find a reverse mapping entry for the given VMA and offset.
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
    use alloc::sync::Arc;
    use x86_64::{structures::paging::PhysFrame, PhysAddr};

    // (Import additional items from your crate as needed.)
    use crate::{
        constants::memory::PAGE_SIZE,
        memory::{frame_allocator::alloc_frame, paging::create_mapping, KERNEL_MAPPER},
    };

    use super::*;

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
            let _vma1 =
                Mm::insert_vma(tree, 0, 500, anon_area.clone(), VmAreaFlags::WRITABLE, true);
            let _vma2 = Mm::insert_vma(
                tree,
                600,
                1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
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
            let _vma = Mm::insert_vma(tree, 0, 500, anon_area.clone(), VmAreaFlags::WRITABLE, true);

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
    /// - The backing pointer of the VM Area matches the anonymous backing area.
    /// - The mapping in the anonymous area correctly returns the physical frame.
    #[test_case]
    async fn test_mm_anon_vm_backing() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area: Arc<dyn VmAreaBacking> = Arc::new(AnonVmArea::new());

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");

        let vm_area = mm.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(
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
        let chain1 = Arc::new(VmaChain {
            offset: faulting_address1_round,
            frame: frame1.into(),
        });
        anon_area.insert_mapping(chain1);

        mm.with_vma_tree(|tree| {
            let found1 = Mm::find_vma(faulting_address1, tree).expect("Should find vma");
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
    async fn test_mm_anon_vm_backing2() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area: Arc<dyn VmAreaBacking> = Arc::new(AnonVmArea::new());

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");
        let frame2 = alloc_frame().expect("Could not allocate PhysFrame");

        mm.with_vma_tree_mutable(|tree| {
            let vm_area = Mm::insert_vma(
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
    async fn test_mm_multiple_vmas() {
        let pml4_frame1 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm1 = Mm::new(pml4_frame1);
        let pml4_frame2 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm2 = Mm::new(pml4_frame2);
        let anon_area = Arc::new(AnonVmArea::new());

        let vm_area1 = mm1.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            )
        });
        let vm_area2 = mm2.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(
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
        let chain = Arc::new(VmaChain {
            offset: faulting_address1_round,
            frame: frame.into(),
        });
        anon_area.insert_mapping(chain);

        let found1 = mm1
            .with_vma_tree(|tree| Mm::find_vma(faulting_address1, tree).expect("Should find vma"));
        let found2 = mm2
            .with_vma_tree(|tree| Mm::find_vma(faulting_address2, tree).expect("Should find vma"));
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
    async fn test_coalesce_left() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = Mm::insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let got_vma1 = Mm::find_vma(0x500, tree).expect("Should find vma");

            let _vma2 = Mm::insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let v1_start = got_vma1.lock().start;
            let v2_start = Mm::find_vma(0x1500, tree)
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
    async fn test_coalesce_right() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = Mm::insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let _vma2 = Mm::insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
        });
        let found = mm.with_vma_tree(|tree| Mm::find_vma(0x1500, tree).expect("Should find vma"));
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
    // #[test_case]
    async fn test_coalesce_both() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(AnonVmArea::new());

        let (got_vma1, got_vma2, got_vma3) = mm.with_vma_tree_mutable(|tree| {
            let _vma1 = Mm::insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let got_vma1 = Mm::find_vma(0x500, tree).expect("Should find vma");

            let _vma2 = Mm::insert_vma(
                tree,
                0x2000,
                0x3000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let _vma3 = Mm::insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                true,
            );
            let got_vma2 = Mm::find_vma(0x1500, tree).expect("Should find vma");
            let got_vma3 = Mm::find_vma(0x2500, tree).expect("Should find vma");

            (got_vma1, got_vma2, got_vma3)
        });
        let start1 = got_vma1.lock().start;
        let start2 = got_vma2.lock().start;
        let start3 = got_vma3.lock().start;
        assert_eq!(start1, start2);
        assert_eq!(start2, start3);
    }

    /// Tests shrinking a VMA from the left side.
    ///
    /// In this test, we create a VMA that spans three pages starting at 0x40000000.  
    /// We populate its reverse mappings with one mapping per page.  
    /// Then we shrink the VMA by removing the leftmost page, so that the new start is shifted
    /// by one page (i.e. new_start = old_start + PAGE_SIZE) while the end remains unchanged.  
    /// The test asserts that:
    /// - The new VMA covers only the right two pages.
    /// - The reverse mappings have been updated so that the surviving mappings are shifted
    ///   (i.e. the mapping for the former second page now has offset 0).
    #[test_case]
    async fn test_shrink_vma_left() {
        // setup
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
                true,
            );
            {
                let locked_vma = vma.lock();
                let mut mappings = locked_vma.backing.mappings().lock();
                // For each page in the VMA, create a mapping and record its offset.
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
        // The reverse mappings should now cover two pages.
        let mappings = locked.backing.mappings().lock();
        assert_eq!(mappings.len(), 2);
        // The surviving offsets should have been shifted so that the leftmost surviving page is offset 0.
        assert!(mappings.contains_key(&0));
        assert!(mappings.contains_key(&(PAGE_SIZE as u64)));
    }

    /// Tests shrinking a VMA from the right side.
    ///
    /// In this test, a VMA spanning three pages are craeted
    /// Its reverse mappings are populated with one mapping per page.  
    /// We then shrink the VMA by removing the rightmost page (i.e. setting new_end = old_end - PAGE_SIZE)
    /// while keeping the start unchanged.  
    /// The test asserts that:
    /// - The resulting VMA covers the left two pages.
    /// - The reverse mappings remain unshifted (i.e. the mapping for the first page is still at offset 0,
    ///   and the second page remains at offset PAGE_SIZE)
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
                true,
            );
            {
                let locked_vma = vma.lock();
                let mut mappings = locked_vma.backing.mappings().lock();
                for i in 0..3 {
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
        let mappings = locked.backing.mappings().lock();
        // two mappings should remain unshifted as we only shrunk the right side
        assert_eq!(mappings.len(), 2);
        assert!(mappings.contains_key(&0));
        assert!(mappings.contains_key(&(PAGE_SIZE as u64)));
    }

    /// Tests shrinking a VMA from both the left and right sides simultaneously.
    ///
    /// In this test, a VMA covering four pages are created and populated with
    /// reverse mappings for each page. We then shrink the VMA by removing one page from the left
    /// and one page from the right, so that the surviving region covers the two middle pages.
    /// The test asserts that:
    /// - The new VMA boundaries are updated to reflect the surviving region.
    /// - The reverse mappings are updated so that the surviving pages have their offsets shifted
    ///   (i.e. the leftmost surviving mapping has offset 0).
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
                true,
            );
            {
                let locked_vma = vma.lock();
                let mut mappings = locked_vma.backing.mappings().lock();
                for i in 0..4 {
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

        // check if backings were updated correctly, there should still
        // be two left from after the shrink (4 allocated initially)
        let mappings = locked.backing.mappings().lock();
        assert_eq!(mappings.len(), 2);
        assert!(mappings.contains_key(&0));
        assert!(mappings.contains_key(&(PAGE_SIZE as u64)));
    }

    /// Tests shrinking a VMA completely so that no pages survive.
    ///
    /// In this test, a VMA covering two pages starting at 0x70000000 is created and populated with
    /// reverse mappings for each page. We then shrink the VMA so that new_start equals new_end,
    /// meaning that the entire VMA is unmapped.  
    ///
    /// This is effectively doing the same thing as a remove_vma, but could simplify code
    /// for munmap()
    ///
    /// The test asserts that:
    /// - The shrink operation returns `None`, indicating that no VMA remains.
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
                true,
            );
            {
                let locked_vma = vma.lock();
                let mut mappings = locked_vma.backing.mappings().lock();
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
        let new_boundary = old_start + PAGE_SIZE as u64; // Remove one page (the entire VMA in this case)
        let shrunk = mm.with_vma_tree_mutable(|tree| {
            let mut mapper = KERNEL_MAPPER.lock();
            Mm::shrink_vma(old_start, new_boundary, new_boundary, &mut *mapper, tree)
        });
        // When the entire VMA is shrunk away, shrink_vma returns None.
        assert!(shrunk.is_none());
    }
}
