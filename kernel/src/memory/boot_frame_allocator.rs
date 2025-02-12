use crate::{
    constants::memory::{FRAME_SIZE, MAX_ALLOCATED_FRAMES},
    serial_println,
};
use limine::memory_map::EntryType;
use limine::request::MemoryMapRequest;
use limine::response::MemoryMapResponse;
use x86_64::{
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size4KiB},
    PhysAddr,
};

#[used]
#[link_section = ".requests"]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

pub struct BootIntoFrameAllocator {
    pub memory_map: &'static MemoryMapResponse,
    next: usize,
    // we note the first and last frame allocated to reallocate later
    first_frame: Option<PhysFrame>,
    last_frame: Option<PhysFrame>,
    allocated_count: usize,
}

impl BootIntoFrameAllocator {
    /// # Safety
    ///
    /// TODO
    pub unsafe fn init() -> Self {
        let memory_map: &MemoryMapResponse = MEMORY_MAP_REQUEST
            .get_response()
            .expect("Memory map request failed");
        BootIntoFrameAllocator {
            memory_map,
            next: 0,
            first_frame: None,
            last_frame: None,
            allocated_count: 0,
        }
    }

    /// scan memory map and map only frames we know we can use
    pub fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        self.memory_map
            .entries()
            .iter()
            .filter(|r| r.entry_type == EntryType::USABLE)
            .map(|r| r.base..=r.base + r.length)
            .flat_map(|r| r.step_by(4096))
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }

    /// gets the frame of a specific physical memory access
    pub fn get_frame(&mut self, addr: u64) -> PhysFrame {
        PhysFrame::containing_address(PhysAddr::new(addr))
    }

    /// returns an iterator that goes over all allocated frames. should only be called
    /// after allocations have happened
    pub fn allocated_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        let start_addr = self
            .first_frame
            .expect("No frames allocated yet")
            .start_address()
            .as_u64();

        (0..self.allocated_count).map(move |i| {
            let addr = start_addr + (i as u64 * FRAME_SIZE as u64);
            PhysFrame::containing_address(PhysAddr::new(addr))
        })
    }

    /// Debug function to print allocated_frames
    pub fn print_allocated_frames(&self) {
        serial_println!("Number of frames allocated: {}", self.allocated_count);
        for frame in self.allocated_frames() {
            serial_println!("Frame at: {:?}", frame.start_address());
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootIntoFrameAllocator {
    /// allocates a frame that we can use; for rudimentary kernel setup
    /// FIXME: Is not efficient due to constant calls to usable_frames()
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = Some(self.usable_frames().nth(self.next)?);
        self.next += 1;

        assert!(self.allocated_count < MAX_ALLOCATED_FRAMES);
        if self.first_frame.is_none() {
            self.first_frame = frame;
        }
        self.last_frame = frame;
        self.allocated_count += 1;

        frame
    }
}

impl FrameDeallocator<Size4KiB> for BootIntoFrameAllocator {
    unsafe fn deallocate_frame(&mut self, _frame: PhysFrame<Size4KiB>) {
        panic!("Cannot deallocate frames for boot frame allocator")
    }
}
