use crate::serial_println;
use alloc::{collections::btree_map::BTreeMap, sync::Arc, vec::Vec};
use bitflags::bitflags;
use core::fmt::Debug;
use spin::Mutex;
use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};

type VmaTree = BTreeMap<usize, Arc<Mutex<VmArea>>>;

/// The overall memory management structure.
#[derive(Debug)]
pub struct Mm {
    /// The BTreeMap of VmAreas
    pub vma_tree: Mutex<VmaTree>,
    /// The level 4 page table
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

/// The three VmArea segments returned from a shrink call
type ShrinkVma = (
    Option<Arc<Mutex<VmArea>>>,
    Option<Arc<Mutex<VmArea>>>,
    Option<Arc<Mutex<VmArea>>>,
);

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
        initial_backing: Arc<VmAreaBackings>,
        flags: VmAreaFlags,
        fd: usize,
        pg_offset: u64,
    ) -> Arc<Mutex<VmArea>> {
        let new_vma = Arc::new(Mutex::new(VmArea::new(
            start,
            end,
            initial_backing.clone(),
            flags,
            fd,
            pg_offset,
        )));

        let new_vma = Self::coalesce_vma_left(new_vma.clone(), tree);
        Self::coalesce_vma_right(new_vma.clone(), tree)
    }

    pub fn coalesce_vma(candidate: Arc<Mutex<VmArea>>, tree: &mut VmaTree) -> Arc<Mutex<VmArea>> {
        let candidate = Self::coalesce_vma_left(candidate, tree);
        Self::coalesce_vma_left(candidate, tree)
    }

    pub fn update_vma_permissions(vma: &Arc<Mutex<VmArea>>, flags: VmAreaFlags) {
        let mut vma_locked = vma.lock();
        vma_locked.flags = flags;
    }

    /// Insert a copied VmArea into the VMA tree.
    ///
    /// Unlike `insert_vma` (which creates a single segment covering the entire region),
    /// this function takes in a segments map to support multiple backing segments.
    pub fn insert_copied_vma(
        tree: &mut VmaTree,
        start: u64,
        end: u64,
        segments: Arc<Mutex<BTreeMap<u64, VmAreaSegment>>>,
        flags: VmAreaFlags,
    ) -> Arc<Mutex<VmArea>> {
        let new_vma = Arc::new(Mutex::new(VmArea::new_copied(start, end, segments, flags)));

        let new_vma = Self::coalesce_vma_left(new_vma.clone(), tree);
        Self::coalesce_vma_right(new_vma.clone(), tree)
    }

    /// Attempts to coalesce the candidate VMA with its left neighbor.
    /// If the left neighbor is adjacent (its end equals candidate's start),
    /// has the same flags, the two VMAs are merged. Otherwise, the
    /// candidate is returned unchanged.
    pub fn coalesce_vma_left(
        candidate: Arc<Mutex<VmArea>>,
        tree: &mut VmaTree,
    ) -> Arc<Mutex<VmArea>> {
        // Retrieve candidate properties.
        let (cand_start, _cand_end, cand_segments, cand_flags) = {
            let cand = candidate.lock();
            (cand.start, cand.end, cand.segments.clone(), cand.flags)
        };

        // cannot do a left merge if there can be no left VMA
        if cand_start == 0 {
            return candidate;
        }

        // Look up the VMA that covers the address just before candidate's start.
        if let Some(left_vma) = Mm::find_vma(cand_start - 1, tree) {
            // TODO: Check backings are of the same type
            // Check that the left VMA is exactly adjacent and compatible.
            let merge_possible = {
                let left = left_vma.lock();
                left.end == cand_start && left.flags == cand_flags
            };

            if merge_possible {
                let left_guard = left_vma.lock();

                let left_segments = left_guard.segments.lock();
                let mut cand_segments = cand_segments.lock();

                let left_len = left_guard.end - left_guard.start;

                let old_offsets: Vec<u64> = cand_segments.keys().cloned().collect();

                // shift backings in candidate vma
                for offset in old_offsets.iter() {
                    if let Some(mut old) = cand_segments.remove(offset) {
                        old.start += left_len;
                        old.end += left_len;
                        cand_segments.insert(offset + left_len, old);
                    }
                }

                candidate.lock().start = left_guard.start;

                tree.remove(&(left_guard.start as usize));

                for segment in left_segments.iter() {
                    cand_segments.insert(*segment.0, segment.1.clone());
                }
            }
        }

        tree.insert(candidate.lock().start as usize, candidate.clone());

        // If no merge occurred, return the candidate unchanged.
        candidate
    }

    /// Attempts to coalesce the candidate VMA with its right neighbor.
    /// If the right neighbor is adjacent (its start equals candidate's end)
    /// and has the same flags, the two VMAs are merged. Otherwise, the
    /// candidate is returned unchanged.
    pub fn coalesce_vma_right(
        candidate: Arc<Mutex<VmArea>>,
        tree: &mut VmaTree,
    ) -> Arc<Mutex<VmArea>> {
        // Retrieve candidate properties.
        let (cand_start, cand_end, cand_segments, cand_flags) = {
            let cand = candidate.lock();
            (cand.start, cand.end, cand.segments.clone(), cand.flags)
        };

        // Look up the VMA that starts exactly at candidate's end.
        if let Some(right_vma) = Mm::find_vma(cand_end, tree) {
            let merge_possible = {
                let right = right_vma.lock();
                right.start == cand_end && right.flags == cand_flags
            };

            if merge_possible {
                let right_guard = right_vma.lock();

                let mut right_segments = right_guard.segments.lock();
                let mut cand_segments = cand_segments.lock();

                // Calculate the candidate's length.
                let cand_len = cand_end - cand_start;

                // For each segment in the right VMA, shift its key and segment offsets
                // by the candidate's length so that they become relative to candidate.start.
                let old_offsets: Vec<u64> = right_segments.keys().cloned().collect();
                for offset in old_offsets.iter() {
                    if let Some(mut seg) = right_segments.remove(offset) {
                        seg.start += cand_len;
                        seg.end += cand_len;
                        right_segments.insert(offset + cand_len, seg);
                    }
                }

                // Merge the (shifted) segments from the right VMA into the candidate's segments.
                for (offset, seg) in right_segments.iter() {
                    cand_segments.insert(*offset, seg.clone());
                }

                candidate.lock().end = right_guard.end;

                // Remove the right VMA from the tree.
                tree.remove(&(cand_end as usize));
            }
        }

        tree.insert(candidate.lock().start as usize, candidate.clone());

        // If no merge occurred, or after merge, return the candidate VMA.
        candidate
    }

    /// Remove the VmArea starting at the given address.
    pub fn remove_vma(start: u64, tree: &mut VmaTree) -> Option<(usize, Arc<Mutex<VmArea>>)> {
        tree.remove_entry(&(start as usize))
    }

    // TODO: VERIFY NO OFF BY ONE ERRORS
    pub fn shrink_vma(
        old_start: u64,
        new_start: u64,
        new_end: u64,
        tree: &mut VmaTree,
    ) -> ShrinkVma {
        // Remove the original VMA from the tree.
        let vma = Mm::remove_vma(old_start, tree).unwrap().1;
        // Record the original end of the VMA.
        let original_end = {
            let v = vma.lock();
            v.end
        };

        let split_point_left = new_start - old_start;
        let split_point_right = new_end - old_start;

        let mut left_segments: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
        let mut middle_segments: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
        let mut right_segments: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();

        {
            // clone the old segments map for iteration.
            let old_segments = {
                let vma_guard = vma.lock();
                vma_guard.segments.clone()
            };
            let old_segments = old_segments.lock();

            for (&old_seg_key, seg) in old_segments.iter() {
                let seg_length = seg.end - seg.start;
                let seg_global_start = old_seg_key; // relative to old_start
                let seg_global_end = seg_global_start + seg_length;

                // guaranteed to be a left only segment
                if seg_global_end <= split_point_left {
                    left_segments.insert(old_seg_key, seg.clone());
                // guaranteed to be a right only segment
                } else if seg_global_start > split_point_right {
                    right_segments.insert(old_seg_key - split_point_right, seg.clone());
                // guaranteed to be a middle only segment
                } else if seg_global_start >= split_point_left
                    && seg_global_end <= split_point_right
                {
                    middle_segments.insert(old_seg_key - split_point_left, seg.clone());
                // spans the left split
                } else if seg_global_start < split_point_left && seg_global_end <= split_point_right
                {
                    let left_part_length = split_point_left - seg_global_start;
                    let left_seg = VmAreaSegment {
                        start: seg.start,
                        end: seg.start + left_part_length,
                        backing: seg.backing.clone(),
                        pg_offset: seg.pg_offset,
                        fd: seg.fd,
                    };
                    left_segments.insert(old_seg_key, left_seg);
                    // the middle part
                    let middle_part_length = seg_global_end - split_point_left;
                    let middle_seg = VmAreaSegment {
                        start: seg.start + left_part_length,
                        end: seg.start + left_part_length + middle_part_length,
                        backing: seg.backing.clone(),
                        pg_offset: seg.pg_offset,
                        fd: seg.fd,
                    };
                    middle_segments.insert(0, middle_seg);
                // spans the right split
                } else if seg_global_start >= split_point_left && seg_global_end > split_point_right
                {
                    let middle_part_length = split_point_right - seg_global_start;
                    let middle_seg = VmAreaSegment {
                        start: seg.start,
                        end: seg.start + middle_part_length,
                        backing: seg.backing.clone(),
                        pg_offset: seg.pg_offset,
                        fd: seg.fd,
                    };
                    middle_segments.insert(old_seg_key - split_point_left, middle_seg);
                    let right_part_length = seg_global_end - split_point_right;
                    let right_seg = VmAreaSegment {
                        start: seg.start + middle_part_length,
                        end: seg.start + middle_part_length + right_part_length,
                        backing: seg.backing.clone(),
                        pg_offset: seg.pg_offset,
                        fd: seg.fd,
                    };
                    right_segments.insert(0, right_seg);
                // spans both splits
                } else if seg_global_start < split_point_left && seg_global_end > split_point_right
                {
                    let left_part_length = split_point_left - seg_global_start;
                    let left_seg = VmAreaSegment {
                        start: seg.start,
                        end: seg.start + left_part_length,
                        backing: seg.backing.clone(),
                        pg_offset: seg.pg_offset,
                        fd: seg.fd,
                    };
                    left_segments.insert(old_seg_key, left_seg);
                    let middle_part_length = split_point_right - split_point_left;
                    let middle_seg = VmAreaSegment {
                        start: seg.start + left_part_length,
                        end: seg.start + left_part_length + middle_part_length,
                        backing: seg.backing.clone(),
                        pg_offset: seg.pg_offset,
                        fd: seg.fd,
                    };
                    middle_segments.insert(0, middle_seg);
                    let right_part_length = seg_global_end - split_point_right;
                    let right_seg = VmAreaSegment {
                        start: seg.start + left_part_length + middle_part_length,
                        end: seg.start + left_part_length + middle_part_length + right_part_length,
                        backing: seg.backing.clone(),
                        pg_offset: seg.pg_offset,
                        fd: seg.fd,
                    };
                    right_segments.insert(0, right_seg);
                }
            }
        }

        // Update the original VMA (left part) with new boundaries and segments.
        {
            let mut vma_guard = vma.lock();
            vma_guard.start = new_start;
            vma_guard.end = new_end;
            // Replace the old segments with the new left_segments.
            vma_guard.segments = Arc::new(Mutex::new(middle_segments));
        }
        tree.insert(new_start as usize, vma.clone());

        let left_vma = if !left_segments.is_empty() {
            let left_vma = Arc::new(Mutex::new(VmArea {
                start: old_start,
                end: new_start,
                segments: Arc::new(Mutex::new(left_segments)),
                flags: {
                    let v = vma.lock();
                    v.flags
                },
            }));
            tree.insert(left_vma.lock().start as usize, left_vma.clone());
            Some(left_vma)
        } else {
            None
        };

        // Create a new VMA for the right (removed) region if there are any segments.
        let right_vma = if !right_segments.is_empty() {
            let right_vma = Arc::new(Mutex::new(VmArea {
                start: new_end,
                end: original_end,
                segments: Arc::new(Mutex::new(right_segments)),
                flags: {
                    let v = vma.lock();
                    v.flags
                },
            }));
            tree.insert(right_vma.lock().start as usize, right_vma.clone());
            Some(right_vma)
        } else {
            None
        };

        (left_vma, Some(vma), right_vma)
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
    pub segments: Arc<Mutex<BTreeMap<u64, VmAreaSegment>>>,
    pub flags: VmAreaFlags,
}

impl VmArea {
    /// Create a new VMA with a single backing segment covering the whole region.
    pub fn new(
        start: u64,
        end: u64,
        initial_backing: Arc<VmAreaBackings>,
        flags: VmAreaFlags,
        fd: usize,
        pg_offset: u64,
    ) -> Self {
        let mut segments = BTreeMap::new();
        // The segment covers the entire VMA: its offsets are relative to `start`.
        segments.insert(
            0,
            VmAreaSegment {
                start: 0,
                end: end - start,
                backing: initial_backing,
                fd,
                pg_offset,
            },
        );
        VmArea {
            start,
            end,
            segments: Arc::new(Mutex::new(segments)),
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
        segments: Arc<Mutex<BTreeMap<u64, VmAreaSegment>>>,
        flags: VmAreaFlags,
    ) -> Self {
        VmArea {
            start,
            end,
            segments,
            flags,
        }
    }

    /// Finds the backing corresponding to a page-aligned offset
    pub fn find_segment(&self, offset: u64) -> VmAreaSegment {
        self.segments.lock().get(&offset).unwrap().clone()
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
    pub backing: Arc<VmAreaBackings>,
    /// file descriptor backed by this segment
    pub fd: usize,
    /// page offset
    pub pg_offset: u64,
}

/// Reverse mapping chain entry linking an offset to a physical page.
#[derive(Debug)]
pub struct VmaChain {
    pub offset: u64,
    pub fd: usize,
    pub frame: PhysFrame,
}

impl VmaChain {
    pub fn new(offset: u64, fd: usize, frame: PhysFrame) -> Self {
        VmaChain { offset, fd, frame }
    }
}

/// Anonymous VM area for managing reverse mappings for anonymous pages.
#[derive(Debug)]
pub struct VmAreaBackings {
    /// Reverse mappings keyed by offset.
    pub mappings: Mutex<BTreeMap<u64, Arc<VmaChain>>>,
    pub vmas: Mutex<Vec<Arc<Mutex<VmArea>>>>,
}

impl Default for VmAreaBackings {
    fn default() -> Self {
        Self::new()
    }
}

impl VmAreaBackings {
    /// Create a new VmAreaBackings with an empty mapping.
    pub fn new() -> Self {
        VmAreaBackings {
            mappings: Mutex::new(BTreeMap::new()),
            vmas: Mutex::new(Vec::new()),
        }
    }

    /// Debug function to print all page-to-frame mappings.
    pub fn print_mappings(&self) {
        for e in self.mappings.lock().iter() {
            serial_println!(
                "Key: {}, Offset: {}, Frame: {:#X}",
                e.0,
                e.1.offset,
                e.1.frame.start_address()
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use x86_64::{
        structures::paging::{Page, PhysFrame},
        PhysAddr, VirtAddr,
    };

    // (Import additional items from your crate as needed.)
    use crate::{
        constants::memory::PAGE_SIZE,
        memory::{frame_allocator::alloc_frame, paging::create_mapping, KERNEL_MAPPER},
    };

    /// Tests insertion and lookup of VM Areas in the memory manager.
    ///
    /// This test creates a memory manager (`Mm`) with a dummy PML4 frame and a
    /// new anonymous backing area (`VmAreaBackings`). It inserts two VM Areas into
    /// the internal VMA tree: one covering addresses `[0, 500)` and another
    /// covering `[600, 1000)`. The test then verifies that looking up addresses
    /// 250 and 750 correctly returns the corresponding VM Areas with the
    /// expected starting addresses.
    #[test_case]
    async fn test_vma_insert_find() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(VmAreaBackings::new());

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = Mm::insert_vma(
                tree,
                0,
                500,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );
            let _vma2 = Mm::insert_vma(
                tree,
                600,
                1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
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
    /// This test creates a memory manager with a dummy PML4 frame and a new
    /// anonymous backing area. It inserts a single VM Area spanning `[0, 500)`
    /// and verifies that it can be found by address lookup. The test then
    /// removes the VM Area starting at address 0 and confirms that subsequent
    /// lookup fails, ensuring that removal works correctly.
    #[test_case]
    async fn test_vma_remove() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(VmAreaBackings::new());

        mm.with_vma_tree_mutable(|tree| {
            // Create a VmArea instance.
            let _vma = Mm::insert_vma(
                tree,
                0,
                500,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );

            let found = Mm::find_vma(250, tree);
            assert_eq!(found.unwrap().lock().start, 0);

            // Remove the VMA starting at address 0.
            let removed = Mm::remove_vma(0, tree).unwrap();
            let removed_start = removed.1.lock().start;
            let found_after = Mm::find_vma(removed_start, tree);
            assert!(found_after.is_none());
        });
    }

    /// Verifies that an anonymous VM backing area correctly maps a faulted
    /// address to its corresponding frame.
    ///
    /// This test sets up a VM Area with an anonymous backing area and allocates
    /// a physical frame. It then simulates a fault at a specific address within
    /// the VM Area and maps that offset to the frame. The test checks that: -
    /// The VM Area can be correctly retrieved by its faulted address. - The
    /// backing pointer of the first segment matches the anonymous backing area.
    /// - The mapping in the anonymous area correctly returns the physical
    ///   frame.
    #[test_case]
    async fn test_anon_vm_backing() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area: Arc<VmAreaBackings> = Arc::new(VmAreaBackings::new());

        let frame = alloc_frame().expect("Could not allocate PhysFrame");

        let vm_area = mm.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            )
        });

        // Calculate the faulting address's aligned offset.
        let faulting_address1: u64 = 0x500;
        let vm_start = vm_area.lock().start;
        let faulting_address1_round = (faulting_address1 - vm_start) & !(PAGE_SIZE as u64 - 1);

        // Map the vm_area and offset to the frame.
        let chain1 = Arc::new(VmaChain {
            offset: faulting_address1_round,
            fd: usize::MAX,
            frame,
        });
        anon_area.insert_mapping(chain1);

        mm.with_vma_tree(|tree| {
            let found1 = Mm::find_vma(faulting_address1, tree).expect("Should find vma");
            let found_vma = found1.lock();
            // Check backing pointer via the first segment.
            let segments = found_vma.segments.lock();
            let seg = segments.get(&0).expect("Segment missing");
            assert!(Arc::ptr_eq(&seg.backing, &anon_area));

            let found1_anon = anon_area
                .find_mapping(faulting_address1_round)
                .expect("Mapping not found");
            assert_eq!(found1_anon.frame.start_address(), frame.start_address())
        });
    }

    /// Verifies that an anonymous VM backing area correctly handles multiple frame mappings.
    ///
    /// This test sets up a VM Area spanning `[0, 0x2000)` with an anonymous backing area and allocates two distinct frames.
    /// It simulates faults at two different addresses within the VM Area and maps each offset to a different frame.
    /// The test asserts that the correct physical frame is returned for each fault offset.
    #[test_case]
    async fn test_anon_vm_backing2() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area: Arc<VmAreaBackings> = Arc::new(VmAreaBackings::new());

        let frame1 = alloc_frame().expect("Could not allocate PhysFrame");
        let frame2 = alloc_frame().expect("Could not allocate PhysFrame");

        mm.with_vma_tree_mutable(|tree| {
            let vm_area = Mm::insert_vma(
                tree,
                0,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );

            let vm_start = vm_area.lock().start;
            let faulting_address1: u64 = 0x500;
            let faulting_address2: u64 = 0x1500;

            let faulting_address1_round = (faulting_address1 - vm_start) & !(PAGE_SIZE as u64 - 1);
            let faulting_address2_round = (faulting_address2 - vm_start) & !(PAGE_SIZE as u64 - 1);

            let chain1 = Arc::new(VmaChain {
                offset: faulting_address1_round,
                fd: usize::MAX,
                frame: frame1,
            });
            let chain2 = Arc::new(VmaChain {
                offset: faulting_address2_round,
                fd: usize::MAX,
                frame: frame2,
            });

            anon_area.insert_mapping(chain1);
            anon_area.insert_mapping(chain2);

            let found = Mm::find_vma(faulting_address1, tree).expect("Should find vma");
            let found_vma = found.lock();
            assert!(Arc::ptr_eq(
                &found_vma.segments.lock().get(&0).unwrap().backing,
                &anon_area
            ));

            let found1_anon = anon_area
                .find_mapping(faulting_address1_round)
                .expect("Mapping not found");
            assert_eq!(found1_anon.frame.start_address(), frame1.start_address());

            let found2_anon = anon_area
                .find_mapping(faulting_address2_round)
                .expect("Mapping not found");
            assert_eq!(found2_anon.frame.start_address(), frame2.start_address())
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
    async fn test_multiple_vmas() {
        let pml4_frame1 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm1 = Mm::new(pml4_frame1);
        let pml4_frame2 = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm2 = Mm::new(pml4_frame2);
        let anon_area = Arc::new(VmAreaBackings::new());

        let vm_area1 = mm1.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(
                tree,
                0,
                0x1000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            )
        });
        let vm_area2 = mm2.with_vma_tree_mutable(|tree| {
            Mm::insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
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
            fd: usize::MAX,
            frame,
        });
        anon_area.insert_mapping(chain);

        let found1 = mm1
            .with_vma_tree(|tree| Mm::find_vma(faulting_address1, tree).expect("Should find vma"));
        let found2 = mm2
            .with_vma_tree(|tree| Mm::find_vma(faulting_address2, tree).expect("Should find vma"));
        let seg1 = found1.lock().segments.lock().get(&0).unwrap().clone();
        let seg2 = found2.lock().segments.lock().get(&0).unwrap().clone();
        assert!(Arc::ptr_eq(&seg1.backing, &seg2.backing));

        let found1_anon = anon_area
            .find_mapping(faulting_address1_round)
            .expect("Mapping not found");
        let found2_anon = anon_area
            .find_mapping(faulting_address2_round)
            .expect("Mapping not found");
        assert_eq!(found1_anon.frame, found2_anon.frame);
    }

    /// Tests coalescing of adjacent VM Areas on the left side.
    ///
    /// This test creates two adjacent VM Areas:
    ///
    /// 1. The left VM Area covers virtual addresses `[0x0000, 0x1000)` using an
    ///    anonymous backing (`anon_area1`) which holds a reverse mapping at
    ///    offset `0` pointing to a physical frame (`aa1_frame`).
    ///
    /// 2. The candidate (right) VM Area covers virtual addresses `[0x1000,
    ///    0x2000)` using another anonymous backing (`anon_area2`) which holds a
    ///    reverse mapping at offset `0` pointing to a physical frame
    ///    (`aa2_frame`).
    ///
    /// When both VM Areas are inserted into the VMA tree, the left coalesce
    /// function merges them into a single VMA spanning `[0x0000, 0x2000)`.
    /// After coalescing, the merged VMA should maintain two segments:
    ///
    /// - A segment starting at offset `0` that, when queried at offset `0`,
    ///   returns the frame from `anon_area1` (`aa1_frame`). - A segment starting
    ///   at offset `0x1000` that, when queried at offset `0`, returns the frame
    ///   from `anon_area2` (`aa2_frame`).
    ///
    /// This test verifies that the left coalescing routine correctly merges the
    /// two adjacent VM Areas and updates the segment mappings accordingly.
    #[test_case]
    async fn test_coalesce_left() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area1 = Arc::new(VmAreaBackings::new());
        let anon_area2 = Arc::new(VmAreaBackings::new());

        let aa1_frame = Arc::new(alloc_frame().unwrap());
        anon_area1.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *aa1_frame)));

        let aa2_frame = Arc::new(alloc_frame().unwrap());
        anon_area2.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *aa2_frame)));

        mm.with_vma_tree_mutable(|tree| {
            let _vma1 = Mm::insert_vma(
                tree,
                0x0000,
                0x1000,
                anon_area1.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );
            let _vma2 = Mm::insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area2.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );
        });

        mm.with_vma_tree(|tree| {
            let vma1 = Mm::find_vma(0x500, tree).expect("Should find vma");
            let got_vma1 = vma1.lock();

            assert_eq!(got_vma1.end, 0x2000);

            // get the frame from this new vma
            assert_eq!(
                got_vma1
                    .find_segment(0x0)
                    .backing
                    .find_mapping(0)
                    .unwrap()
                    .frame,
                *aa1_frame
            );

            assert_eq!(
                got_vma1
                    .find_segment(0x1000)
                    .backing
                    .find_mapping(0)
                    .unwrap()
                    .frame,
                *aa2_frame
            );
        })
    }

    /// Tests coalescing of adjacent VM Areas on the right.
    ///
    /// This test creates two VM Areas:
    /// 1. The left VM Area covers addresses [0x0000, 0x1000) using an anonymous
    ///    backing (`anon_area1`) that has a reverse mapping at offset 0
    ///    pointing to a physical frame (`aa1_frame`).
    /// 2. The right VM Area covers addresses [0x1000, 0x2000) using a different
    ///    anonymous backing (`anon_area2`) that has a reverse mapping at offset
    ///    0 pointing to a physical frame (`aa2_frame`).
    ///
    /// After inserting both VM Areas into the VMA tree, the left VMA is
    /// coalesced with its right neighbor via `coalesce_vma_right`. The
    /// resulting merged VMA is expected to span [0x0000, 0x2000) with two
    /// segments: - A segment at key 0 that returns `aa1_frame` when looking up
    /// offset 0. - A segment at key 0x1000 (shifted from the right VMA) that
    /// returns `aa2_frame` when looking up offset 0.
    #[test_case]
    async fn test_coalesce_right() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        // Create two anonymous backings.
        let anon_area1 = Arc::new(VmAreaBackings::new());
        let anon_area2 = Arc::new(VmAreaBackings::new());

        // Allocate frames and insert reverse mappings.
        let aa1_frame = Arc::new(alloc_frame().unwrap());
        anon_area1.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *aa1_frame)));

        let aa2_frame = Arc::new(alloc_frame().unwrap());
        anon_area2.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *aa2_frame)));

        mm.with_vma_tree_mutable(|tree| {
            // Insert left VMA covering [0x0000, 0x1000) with anon_area1.
            let _vma_left = Mm::insert_vma(
                tree,
                0x0000,
                0x1000,
                anon_area1.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );
            // Insert right VMA covering [0x1000, 0x2000) with anon_area2.
            let _vma_right = Mm::insert_vma(
                tree,
                0x1000,
                0x2000,
                anon_area2.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );
        });

        mm.with_vma_tree(|tree| {
            let merged_vma = Mm::find_vma(0x0000, tree).expect("Merged VMA not found");
            let merged_locked = merged_vma.lock();

            // The merged VMA should span from 0x0000 to 0x2000.
            assert_eq!(merged_locked.start, 0x0000);
            assert_eq!(merged_locked.end, 0x2000);

            // Check that the reverse mappings in the merged segments are correct.
            assert_eq!(
                merged_locked
                    .find_segment(0x0)
                    .backing
                    .find_mapping(0)
                    .unwrap()
                    .frame,
                *aa1_frame
            );

            assert_eq!(
                merged_locked
                    .find_segment(0x1000)
                    .backing
                    .find_mapping(0)
                    .unwrap()
                    .frame,
                *aa2_frame
            );
        });
    }

    /// Tests coalescing of two adjacent VM Areas when each VMA is composed of multiple segments.
    ///
    /// This test creates two VM Areas:
    ///
    /// 1. The left VM Area spans virtual addresses [0x0000, 0x2000) and is made up of two segments:
    ///    - A segment covering [0x0000, 0x1000) that uses an anonymous backing (`anon_area1`),
    ///      with a reverse mapping at offset 0 pointing to a physical frame (`frame_left_seg1`).
    ///    - A segment covering [0x1000, 0x2000) that uses a different anonymous backing (`anon_area2`),
    ///      with a reverse mapping at offset 0 pointing to another physical frame (`frame_left_seg2`).
    ///
    /// 2. The candidate VM Area spans [0x2000, 0x4000) and also has two segments:
    ///    - A segment (initially keyed at 0) covering [0x2000, 0x3000) using anonymous backing (`anon_area3`)
    ///      with a reverse mapping at offset 0 for a physical frame (`frame_cand_seg1`).
    ///    - A segment (initially keyed at 0x1000) covering [0x3000, 0x4000) using another anonymous backing (`anon_area4`)
    ///      with a reverse mapping at offset 0 for a physical frame (`frame_cand_seg2`).
    ///
    /// After both VM Areas are inserted into the VMA tree, the candidate VM Area is coalesced with its
    /// left neighbor. The expected outcome is that the merged VM Area spans [0x0000, 0x4000) and contains
    /// four segments:
    ///
    /// - The left VM Area’s segments remain at keys 0 and 0x1000.
    /// - The candidate VM Area’s segments are shifted by 0x2000 (the difference between the candidate’s start and the left’s start),
    ///   resulting in segments at keys 0x2000 and 0x3000.
    ///
    /// Finally, the test verifies that each segment’s backing correctly returns its associated physical frame
    /// (when looking up a reverse mapping at offset 0).
    #[test_case]
    async fn test_coalesce_left_multiple_segments() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        // Create four anonymous backings.
        let anon_area1 = Arc::new(VmAreaBackings::new());
        let anon_area2 = Arc::new(VmAreaBackings::new());
        let anon_area3 = Arc::new(VmAreaBackings::new());
        let anon_area4 = Arc::new(VmAreaBackings::new());

        // Allocate frames for left VMA segments.
        let frame_left_seg1 = Arc::new(alloc_frame().unwrap());
        let frame_left_seg2 = Arc::new(alloc_frame().unwrap());
        // Insert reverse mappings at offset 0 in the left VMA's backings.
        anon_area1.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_left_seg1)));
        anon_area2.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_left_seg2)));

        // Allocate frames for candidate VMA segments.
        let frame_cand_seg1 = Arc::new(alloc_frame().unwrap());
        let frame_cand_seg2 = Arc::new(alloc_frame().unwrap());
        anon_area3.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_cand_seg1)));
        anon_area4.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_cand_seg2)));

        // Insert left VMA with two segments: covering [0x0000, 0x2000)
        mm.with_vma_tree_mutable(|tree| {
            let mut segments_left: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
            // Segment covering [0, 0x1000) using anon_area1.
            segments_left.insert(
                0,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area1.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            // Segment covering [0x1000, 0x2000) using anon_area2.
            segments_left.insert(
                0x1000,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area2.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            let _vma_left = Mm::insert_copied_vma(
                tree,
                0x0000,
                0x2000,
                Arc::new(Mutex::new(segments_left)),
                VmAreaFlags::WRITABLE,
            );

            // Insert candidate VMA with two segments: covering [0x2000, 0x4000)
            let mut segments_cand: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
            // Candidate's first segment covering [0, 0x1000) using anon_area3.
            segments_cand.insert(
                0,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area3.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            // Candidate's second segment covering [0x1000, 0x2000) using anon_area4.
            segments_cand.insert(
                0x1000,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area4.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            let _vma_cand = Mm::insert_copied_vma(
                tree,
                0x2000,
                0x4000,
                Arc::new(Mutex::new(segments_cand)),
                VmAreaFlags::WRITABLE,
            );
        });

        // Now, coalesce the candidate VMA with its left neighbor.
        mm.with_vma_tree_mutable(|tree| {
            // Look up candidate VMA (which starts at 0x2000).
            let vma_cand = Mm::find_vma(0x2000, tree).expect("Candidate VMA not found");
            let merged = Mm::coalesce_vma_left(vma_cand, tree);
            let merged_locked = merged.lock();

            // The merged VMA should span from 0x0000 to 0x4000.
            assert_eq!(merged_locked.start, 0x0000);
            assert_eq!(merged_locked.end, 0x4000);

            // We then check that the reverse mappings are available and return the correct frames.
            let seg1 = merged_locked.find_segment(0);
            let seg2 = merged_locked.find_segment(0x1000);
            let seg3 = merged_locked.find_segment(0x2000);
            let seg4 = merged_locked.find_segment(0x3000);

            // Check that each segment's backing returns the expected frame from offset 0.
            assert_eq!(
                seg1.backing.find_mapping(0).unwrap().frame,
                *frame_left_seg1
            );
            assert_eq!(
                seg2.backing.find_mapping(0).unwrap().frame,
                *frame_left_seg2
            );
            assert_eq!(
                seg3.backing.find_mapping(0).unwrap().frame,
                *frame_cand_seg1
            );
            assert_eq!(
                seg4.backing.find_mapping(0).unwrap().frame,
                *frame_cand_seg2
            );
        });
    }

    /// Tests coalescing of two adjacent VM Areas when each VMA is composed of multiple segments,
    /// using a right-side merge.
    ///
    /// This test creates two VM Areas:
    ///
    /// 1. The left VM Area spans virtual addresses `[0x0000, 0x2000)` and is composed of two segments:
    ///    - A segment covering `[0x0000, 0x1000)` that uses an anonymous backing (`anon_area1`),
    ///      with a reverse mapping at offset `0` pointing to a physical frame (`frame_left_seg1`).
    ///    - A segment covering `[0x1000, 0x2000)` that uses a different anonymous backing (`anon_area2`),
    ///      with a reverse mapping at offset `0` pointing to another physical frame (`frame_left_seg2`).
    ///
    /// 2. The right VM Area spans `[0x2000, 0x4000)` and is also composed of two segments:
    ///    - A segment (initially keyed at `0`) covering `[0x2000, 0x3000)` using anonymous backing (`anon_area3`)
    ///      with a reverse mapping at offset `0` for a physical frame (`frame_right_seg1`).
    ///    - A segment (initially keyed at `0x1000`) covering `[0x3000, 0x4000)` using another anonymous backing (`anon_area4`)
    ///      with a reverse mapping at offset `0` for a physical frame (`frame_right_seg2`).
    ///
    /// After both VM Areas are inserted into the VMA tree, the right coalesce function is invoked on the left VM Area.
    /// This operation merges the left VMA with its right neighbor, shifting the right VMA’s segments by the left VMA’s length
    /// (i.e. `0x2000`), and resulting in a merged VMA spanning `[0x0000, 0x4000)`.
    ///
    /// The merged VMA is expected to contain four segments:
    /// - The left VM Area’s segments remain at keys `0` and `0x1000`.
    /// - The right VM Area’s segments are shifted by `0x2000`, resulting in segments at keys `0x2000` and `0x3000`.
    ///
    /// Finally, the test verifies that each segment’s backing correctly returns its associated physical frame
    /// (when looking up a reverse mapping at offset `0`).
    #[test_case]
    async fn test_coalesce_right_multiple_segments() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        // Create four anonymous backings.
        let anon_area1 = Arc::new(VmAreaBackings::new());
        let anon_area2 = Arc::new(VmAreaBackings::new());
        let anon_area3 = Arc::new(VmAreaBackings::new());
        let anon_area4 = Arc::new(VmAreaBackings::new());

        // Allocate frames for left VMA segments.
        let frame_left_seg1 = Arc::new(alloc_frame().unwrap());
        let frame_left_seg2 = Arc::new(alloc_frame().unwrap());
        anon_area1.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_left_seg1)));
        anon_area2.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_left_seg2)));

        // Allocate frames for right VMA segments.
        let frame_right_seg1 = Arc::new(alloc_frame().unwrap());
        let frame_right_seg2 = Arc::new(alloc_frame().unwrap());
        anon_area3.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_right_seg1)));
        anon_area4.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_right_seg2)));

        // Insert left VMA with two segments: covering [0x0000, 0x2000)
        mm.with_vma_tree_mutable(|tree| {
            let mut segments_left: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
            segments_left.insert(
                0,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area1.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            segments_left.insert(
                0x1000,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area2.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            let _vma_left = Mm::insert_copied_vma(
                tree,
                0x0000,
                0x2000,
                Arc::new(Mutex::new(segments_left)),
                VmAreaFlags::WRITABLE,
            );

            // Insert right VMA with two segments: covering [0x2000, 0x4000)
            let mut segments_right: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
            segments_right.insert(
                0,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area3.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            segments_right.insert(
                0x1000,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area4.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            let _vma_right = Mm::insert_copied_vma(
                tree,
                0x2000,
                0x4000,
                Arc::new(Mutex::new(segments_right)),
                VmAreaFlags::WRITABLE,
            );
        });

        // Now, coalesce the left VMA with its right neighbor using the right coalesce function.
        mm.with_vma_tree_mutable(|tree| {
            // Look up the left VMA (which starts at 0x0000).
            let vma_left = Mm::find_vma(0x0000, tree).expect("Left VMA not found");
            let merged = Mm::coalesce_vma_right(vma_left, tree);
            let merged_locked = merged.lock();

            // The merged VMA should span from 0x0000 to 0x4000.
            assert_eq!(merged_locked.start, 0x0000);
            assert_eq!(merged_locked.end, 0x4000);

            // Verify the segments:
            // Left VMA’s segments remain at keys 0 and 0x1000.
            // Right VMA’s segments are shifted by 0x2000, resulting in keys 0x2000 and 0x3000.
            let seg1 = merged_locked.find_segment(0);
            let seg2 = merged_locked.find_segment(0x1000);
            let seg3 = merged_locked.find_segment(0x2000);
            let seg4 = merged_locked.find_segment(0x3000);

            assert_eq!(
                seg1.backing.find_mapping(0).unwrap().frame,
                *frame_left_seg1
            );
            assert_eq!(
                seg2.backing.find_mapping(0).unwrap().frame,
                *frame_left_seg2
            );
            assert_eq!(
                seg3.backing.find_mapping(0).unwrap().frame,
                *frame_right_seg1
            );
            assert_eq!(
                seg4.backing.find_mapping(0).unwrap().frame,
                *frame_right_seg2
            );
        });
    }

    /// Tests coalescing on both the left and right sides in a three-VM Area scenario with multiple segments.
    ///
    /// This test creates three adjacent VM Areas:
    ///
    /// 1. The left VM Area spans `[0x0000, 0x2000)` and consists of two segments:
    ///    - A segment at key `0` covering `[0x0000, 0x1000)` using anonymous backing (`anon_area1`),
    ///      with a reverse mapping at offset `0` pointing to a physical frame (`frame_left_seg1`).
    ///    - A segment at key `0x1000` covering `[0x1000, 0x2000)` using a different anonymous backing (`anon_area2`),
    ///      with a reverse mapping at offset `0` pointing to another physical frame (`frame_left_seg2`).
    ///
    /// 2. The middle VM Area spans `[0x2000, 0x4000)` and consists of two segments:
    ///    - A segment at key `0` covering `[0x2000, 0x3000)` using anonymous backing (`anon_area3`),
    ///      with a reverse mapping at offset `0` pointing to a physical frame (`frame_mid_seg1`).
    ///    - A segment at key `0x1000` covering `[0x3000, 0x4000)` using another anonymous backing (`anon_area4`),
    ///      with a reverse mapping at offset `0` pointing to a physical frame (`frame_mid_seg2`).
    ///
    /// 3. The right VM Area spans `[0x4000, 0x6000)` and consists of two segments:
    ///    - A segment at key `0` covering `[0x4000, 0x5000)` using anonymous backing (`anon_area5`),
    ///      with a reverse mapping at offset `0` pointing to a physical frame (`frame_right_seg1`).
    ///    - A segment at key `0x1000` covering `[0x5000, 0x6000)` using another anonymous backing (`anon_area6`),
    ///      with a reverse mapping at offset `0` pointing to a physical frame (`frame_right_seg2`).
    ///
    /// After inserting all three VM Areas into the VMA tree, the test forces coalescing on the middle VMA:
    /// first calling `coalesce_vma_left` (merging it with the left neighbor) and then `coalesce_vma_right`
    /// (merging the result with the right neighbor). The final merged VMA is expected to span `[0x0000, 0x6000)`
    /// with six segments at keys:
    /// - `0` and `0x1000` from the left VM Area,
    /// - `0x2000` and `0x3000` from the middle VM Area (shifted by `0x2000`), and
    /// - `0x4000` and `0x5000` from the right VM Area (shifted by `0x4000`).
    ///
    /// The test then verifies that each segment’s backing returns the expected physical frame (when querying offset `0`).
    #[test_case]
    async fn test_coalesce_both_sides_multiple_segments() {
        // Create a dummy PML4 frame.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        // Create six anonymous backings.
        let anon_area1 = Arc::new(VmAreaBackings::new());
        let anon_area2 = Arc::new(VmAreaBackings::new());
        let anon_area3 = Arc::new(VmAreaBackings::new());
        let anon_area4 = Arc::new(VmAreaBackings::new());
        let anon_area5 = Arc::new(VmAreaBackings::new());
        let anon_area6 = Arc::new(VmAreaBackings::new());

        // Allocate physical frames.
        let frame_left_seg1 = Arc::new(alloc_frame().unwrap());
        let frame_left_seg2 = Arc::new(alloc_frame().unwrap());
        let frame_mid_seg1 = Arc::new(alloc_frame().unwrap());
        let frame_mid_seg2 = Arc::new(alloc_frame().unwrap());
        let frame_right_seg1 = Arc::new(alloc_frame().unwrap());
        let frame_right_seg2 = Arc::new(alloc_frame().unwrap());

        // Insert reverse mappings at offset 0 for each backing.
        anon_area1.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_left_seg1)));
        anon_area2.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_left_seg2)));
        anon_area3.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_mid_seg1)));
        anon_area4.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_mid_seg2)));
        anon_area5.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_right_seg1)));
        anon_area6.insert_mapping(Arc::new(VmaChain::new(0x0, usize::MAX, *frame_right_seg2)));

        // Insert left VM Area: spans [0x0000, 0x2000) with two segments.
        mm.with_vma_tree_mutable(|tree| {
            let mut segments_left: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
            segments_left.insert(
                0,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area1.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            segments_left.insert(
                0x1000,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area2.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            let _vma_left = Mm::insert_copied_vma(
                tree,
                0x0000,
                0x2000,
                Arc::new(Mutex::new(segments_left)),
                VmAreaFlags::WRITABLE,
            );

            // Insert right VM Area: spans [0x4000, 0x6000) with two segments.
            let mut segments_right: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
            segments_right.insert(
                0,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area5.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            segments_right.insert(
                0x1000,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area6.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            let _vma_right = Mm::insert_copied_vma(
                tree,
                0x4000,
                0x6000,
                Arc::new(Mutex::new(segments_right)),
                VmAreaFlags::WRITABLE,
            );

            // Insert middle VM Area: spans [0x2000, 0x4000) with two segments.
            // Should trigger a coalesce on both sides
            let mut segments_mid: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
            segments_mid.insert(
                0,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area3.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            segments_mid.insert(
                0x1000,
                VmAreaSegment {
                    start: 0,
                    end: 0x1000,
                    backing: anon_area4.clone(),
                    pg_offset: 0,
                    fd: usize::MAX,
                },
            );
            let _mid_vma = Mm::insert_copied_vma(
                tree,
                0x2000,
                0x4000,
                Arc::new(Mutex::new(segments_mid)),
                VmAreaFlags::WRITABLE,
            );
        });

        // Verify that the final merged VMA spans [0x0000, 0x6000) and has the expected segments.
        mm.with_vma_tree(|tree| {
            let merged_vma = Mm::find_vma(0x0000, tree).expect("Merged VMA not found");
            let merged_locked = merged_vma.lock();

            // Final merged VMA should span from 0x0000 to 0x6000.
            assert_eq!(merged_locked.start, 0x0000);
            assert_eq!(merged_locked.end, 0x6000);

            // Expected segment keys:
            // - Left VMA’s segments remain at keys 0 and 0x1000.
            // - Middle VMA’s segments are shifted by 0x2000, becoming keys 0x2000 and 0x3000.
            // - Right VMA’s segments are shifted by 0x4000, becoming keys 0x4000 and 0x5000.
            let seg1 = merged_locked.find_segment(0);
            let seg2 = merged_locked.find_segment(0x1000);
            let seg3 = merged_locked.find_segment(0x2000);
            let seg4 = merged_locked.find_segment(0x3000);
            let seg5 = merged_locked.find_segment(0x4000);
            let seg6 = merged_locked.find_segment(0x5000);

            assert_eq!(
                seg1.backing.find_mapping(0).unwrap().frame,
                *frame_left_seg1
            );
            assert_eq!(
                seg2.backing.find_mapping(0).unwrap().frame,
                *frame_left_seg2
            );
            assert_eq!(seg3.backing.find_mapping(0).unwrap().frame, *frame_mid_seg1);
            assert_eq!(seg4.backing.find_mapping(0).unwrap().frame, *frame_mid_seg2);
            assert_eq!(
                seg5.backing.find_mapping(0).unwrap().frame,
                *frame_right_seg1
            );
            assert_eq!(
                seg6.backing.find_mapping(0).unwrap().frame,
                *frame_right_seg2
            );
        });
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
        let anon_area = Arc::new(VmAreaBackings::new());
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
                usize::MAX,
                0,
            );
            {
                let locked_vma = vma.lock();
                let segments = locked_vma.segments.lock();
                let seg = segments.get(&0).expect("Segment missing");
                let mut mappings = seg.backing.mappings.lock();
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
                            fd: usize::MAX,
                            frame,
                        }),
                    );
                }
            }
        });

        let new_start = old_start + PAGE_SIZE as u64;
        let new_end = old_end;
        let shrunk = mm
            .with_vma_tree_mutable(|tree| Mm::shrink_vma(old_start, new_start, new_end, tree))
            .1;
        assert!(shrunk.is_some());
        let vma = shrunk.unwrap();
        let locked = vma.lock();
        assert_eq!(locked.start, new_start);
        assert_eq!(locked.end, new_end);
        let segments = locked.segments.lock();
        let seg = segments.get(&0).expect("Segment missing");
        let mappings = seg.backing.mappings.lock();
        assert_eq!(mappings.len(), 3);
        // The surviving offsets should have been shifted so that the leftmost surviving mapping is at offset 0.
        assert!(mappings.contains_key(&0));
        assert!(mappings.contains_key(&(PAGE_SIZE as u64)));
    }

    /// Tests shrinking (splitting) a VMA from both left and right sides when the VMA is composed
    /// of multiple segments, with page-aligned boundaries and without modifying the VmChains (reverse mappings).
    ///
    /// The original VMA spans [0x0, 0x5000) and is composed of three segments:
    ///
    /// 1. Segment A covers [0x0, 0x2000) using `anon_area_a` with a reverse mapping at offset 0 returning `frame_a`.
    /// 2. Segment B covers [0x2000, 0x3000) using `anon_area_b` with a reverse mapping at offset 0 returning `frame_b`.
    /// 3. Segment C covers [0x3000, 0x5000) using `anon_area_c` with a reverse mapping at offset 0 returning `frame_c`.
    ///
    /// We then shrink the VMA so that the surviving region becomes [0x1000, 0x4000). The function returns
    /// a triple: (Option<left_vma>, Option<middle_vma>, Option<right_vma>), where:
    /// - The left VMA spans [0x0, 0x1000) and should contain the left portion of Segment A.
    /// - The middle (surviving) VMA spans [0x1000, 0x4000) and should contain:
    ///   • The right portion of Segment A ([0x1000, 0x2000)) with new key 0.
    ///   • All of Segment B ([0x2000, 0x3000)) with new key 0x1000.
    ///   • The left portion of Segment C ([0x3000, 0x4000)) with new key 0x2000.
    /// - The right VMA spans [0x4000, 0x5000) and should contain the right portion of Segment C.
    #[test_case]
    async fn test_shrink_vma_split_both_multiple_segments() {
        // Create a dummy PML4 frame and memory manager.
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);

        // Original VMA boundaries: [0x0, 0x5000).
        let old_start = 0x0;
        let old_end = 0x5000;
        // We shrink so that the surviving (middle) region becomes [0x1000, 0x4000).
        let new_start = 0x1000;
        let new_end = 0x4000;

        // Create anonymous backings.
        let anon_area_a = Arc::new(VmAreaBackings::new());
        let anon_area_b = Arc::new(VmAreaBackings::new());
        let anon_area_c = Arc::new(VmAreaBackings::new());

        // Allocate physical frames and set up reverse mappings (all at offset 0).
        // Segment A: covers [0x0, 0x2000)
        let frame_a_a = Arc::new(alloc_frame().unwrap());
        let frame_a_b = Arc::new(alloc_frame().unwrap());
        anon_area_a.insert_mapping(Arc::new(VmaChain::new(0, usize::MAX, *frame_a_a)));
        anon_area_a.insert_mapping(Arc::new(VmaChain::new(0x1000, usize::MAX, *frame_a_b)));

        // Segment B: covers [0x2000, 0x3000)
        let frame_b = Arc::new(alloc_frame().unwrap());
        anon_area_b.insert_mapping(Arc::new(VmaChain::new(0, usize::MAX, *frame_b)));

        // Segment C: covers [0x3000, 0x5000)
        let frame_c_a = Arc::new(alloc_frame().unwrap());
        let frame_c_b = Arc::new(alloc_frame().unwrap());
        anon_area_c.insert_mapping(Arc::new(VmaChain::new(0, usize::MAX, *frame_c_a)));
        anon_area_c.insert_mapping(Arc::new(VmaChain::new(0x1000, usize::MAX, *frame_c_b)));

        // Build the original segments map.
        let mut segments: BTreeMap<u64, VmAreaSegment> = BTreeMap::new();
        // Segment A at key 0, covering [0x0, 0x2000).
        segments.insert(
            0,
            VmAreaSegment {
                start: 0,
                end: 0x2000,
                backing: anon_area_a.clone(),
                fd: usize::MAX,
                pg_offset: 0,
            },
        );
        // Segment B at key 0x2000, covering [0x2000, 0x3000).
        segments.insert(
            0x2000,
            VmAreaSegment {
                start: 0,
                end: 0x1000,
                backing: anon_area_b.clone(),
                fd: usize::MAX,
                pg_offset: 0,
            },
        );
        // Segment C at key 0x3000, covering [0x3000, 0x5000).
        segments.insert(
            0x3000,
            VmAreaSegment {
                start: 0,
                end: 0x2000,
                backing: anon_area_c.clone(),
                pg_offset: 0,
                fd: usize::MAX,
            },
        );

        // Insert the original VMA using our segments map.
        mm.with_vma_tree_mutable(|tree| {
            let _vma = Mm::insert_copied_vma(
                tree,
                old_start,
                old_end,
                Arc::new(Mutex::new(segments)),
                VmAreaFlags::WRITABLE,
            );
        });

        // Call shrink_vma to split the VMA into three parts.
        // The function returns a triple: (Option<left_vma>, Option<middle_vma>, Option<right_vma>).
        let (left_vma_opt, middle_vma_opt, right_vma_opt) =
            mm.with_vma_tree_mutable(|tree| Mm::shrink_vma(old_start, new_start, new_end, tree));

        // Verify the left VMA.
        {
            let left_vma = left_vma_opt.expect("Left VMA should exist");
            let left_locked = left_vma.lock();
            // Left VMA should span [0x0, 0x1000).
            assert_eq!(left_locked.start, old_start);
            assert_eq!(left_locked.end, new_start);
            // Expect the left part of Segment A: originally [0x0, 0x2000) becomes left portion [0x0, 0x1000).
            let seg_a_left = left_locked.find_segment(0);
            assert_eq!(seg_a_left.end - seg_a_left.start, 0x1000);
            serial_println!("Seg_A left: {:#?}", seg_a_left);
            assert_eq!(
                seg_a_left
                    .backing
                    .find_mapping(seg_a_left.start)
                    .unwrap()
                    .frame,
                *frame_a_a
            );
        }

        // Verify the middle (surviving) VMA.
        {
            let middle_vma = middle_vma_opt.expect("Middle VMA should exist");
            let middle_locked = middle_vma.lock();
            // Middle VMA should span [0x1000, 0x4000).
            assert_eq!(middle_locked.start, new_start);
            assert_eq!(middle_locked.end, new_end);
            // In the middle VMA, we expect:
            // - The right part of Segment A: originally [0x0, 0x2000) yields surviving portion [0x1000, 0x2000).
            //   New key = 0x1000 - 0x1000 = 0, length = 0x2000 - 0x1000 = 0x1000.
            let seg_a_right = middle_locked.find_segment(0);
            assert_eq!(seg_a_right.end - seg_a_right.start, 0x1000);
            assert_eq!(
                seg_a_right
                    .backing
                    .find_mapping(seg_a_right.start)
                    .unwrap()
                    .frame,
                *frame_a_b
            );

            // - Segment B: originally at key 0x2000 becomes 0x2000 - 0x1000 = 0x1000, length = 0x1000.
            let seg_b = middle_locked.find_segment(0x1000);
            assert_eq!(seg_b.end - seg_b.start, 0x1000);
            assert_eq!(
                seg_b.backing.find_mapping(seg_b.start).unwrap().frame,
                *frame_b
            );

            // - The left part of Segment C: originally covering [0x3000, 0x5000) yields surviving portion [0x3000, 0x4000).
            //   New key = 0x3000 - 0x1000 = 0x2000, length = 0x4000 - 0x3000 = 0x1000.
            let seg_c_left = middle_locked.find_segment(0x2000);
            assert_eq!(seg_c_left.end - seg_c_left.start, 0x1000);
            assert_eq!(
                seg_c_left
                    .backing
                    .find_mapping(seg_c_left.start)
                    .unwrap()
                    .frame,
                *frame_c_a
            );
        }

        // Verify the right VMA.
        {
            let right_vma = right_vma_opt.expect("Right VMA should exist");
            let right_locked = right_vma.lock();
            // Right VMA should span [0x4000, 0x5000).
            assert_eq!(right_locked.start, new_end);
            assert_eq!(right_locked.end, old_end);
            // so the right portion is [0x4000, 0x5000).
            // In the right VMA coordinate space, new key = 0x4000 - 0x4000 = 0, length = 0x5000 - 0x4000 = 0x1000.
            let seg_c_right = right_locked.find_segment(0);
            assert_eq!(seg_c_right.end - seg_c_right.start, 0x1000);
            assert_eq!(
                seg_c_right
                    .backing
                    .find_mapping(seg_c_right.start)
                    .unwrap()
                    .frame,
                *frame_c_b
            );
        }
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
        let anon_area = Arc::new(VmAreaBackings::new());
        let old_start = 0x60000000;
        let old_end = old_start + 4 * PAGE_SIZE as u64;

        mm.with_vma_tree_mutable(|tree| {
            let vma = Mm::insert_vma(
                tree,
                old_start,
                old_end,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );
            {
                let locked_vma = vma.lock();
                let segments = locked_vma.segments.lock();
                let seg = segments.get(&0).expect("Segment missing");
                let mut mappings = seg.backing.mappings.lock();
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
                            fd: usize::MAX,
                            frame,
                        }),
                    );
                }
            }
        });

        // Shrink both sides: remove the leftmost and rightmost pages.
        let new_start = old_start + PAGE_SIZE as u64;
        let new_end = old_end - PAGE_SIZE as u64;
        let shrunk_left = mm
            .with_vma_tree_mutable(|tree| Mm::shrink_vma(old_start, new_start, new_end, tree))
            .1;
        assert!(shrunk_left.is_some());

        let vma = shrunk_left.unwrap();
        let locked = vma.lock();
        assert_eq!(locked.start, new_start);
        assert_eq!(locked.end, new_end);

        let new_start = old_start + PAGE_SIZE as u64;
        let new_end = old_end - PAGE_SIZE as u64;
        let shrunk_left =
            mm.with_vma_tree_mutable(|tree| Mm::shrink_vma(old_start, new_start, new_end, tree).1);
        assert!(shrunk_left.is_some());

        let vma = shrunk_left.unwrap();
        let locked = vma.lock();
        assert_eq!(locked.start, new_start);
        assert_eq!(locked.end, new_end);

        let segments = locked.segments.lock();
        let seg = segments.get(&0).expect("Segment missing");
        let mappings = seg.backing.mappings.lock();
        // After shrink, expect two mappings.
        assert_eq!(mappings.len(), 2);
        assert!(mappings.contains_key(&0));
        assert!(mappings.contains_key(&(PAGE_SIZE as u64)));
    }

    /// Tests shrinking a VMA completely so that no pages survive.
    ///
    /// In this test, a VMA covering two pages is created and populated with
    /// reverse mappings for each page. We then shrink the VMA so that new_start
    /// equals new_end, meaning that the entire VMA is unmapped. This is similar
    /// to munmap().
    #[test_case]
    async fn test_shrink_vma_whole() {
        let pml4_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        let mm = Mm::new(pml4_frame);
        let anon_area = Arc::new(VmAreaBackings::new());
        let old_start = 0x70000000;
        let old_end = old_start + 2 * PAGE_SIZE as u64;

        mm.with_vma_tree_mutable(|tree| {
            let vma = Mm::insert_vma(
                tree,
                old_start,
                old_end,
                anon_area.clone(),
                VmAreaFlags::WRITABLE,
                usize::MAX,
                0,
            );
            {
                let locked_vma = vma.lock();
                let segments = locked_vma.segments.lock();
                let seg = segments.get(&0).expect("Segment missing");
                let mut mappings = seg.backing.mappings.lock();
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
                            fd: usize::MAX,
                            frame,
                        }),
                    );
                }
            }
        });

        // Shrink whole: new_start == new_end, so no pages remain.
        let new_boundary = old_start + PAGE_SIZE as u64;
        let shrunk = mm.with_vma_tree_mutable(|tree| {
            Mm::shrink_vma(old_start, new_boundary, new_boundary, tree)
        });
        // When the entire VMA is shrunk away, shrink_vma returns None.
        assert!(shrunk.0.is_none());
    }
}
