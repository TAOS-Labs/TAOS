use crate::debug_println;
use alloc::collections::BTreeMap;
use x86_64::{PhysAddr, VirtAddr};

/// A list of all the TRB types and the values associated with them.
pub enum TrbTypes {
    Reserved = 0,
    Normal = 1,
    SetupStage = 2,
    DataStage = 3,
    StatusStage = 4,
    ISOCH = 5,
    Link = 6,
    EventData = 7,
    NoOp = 8,
    EnableSlotCmd = 9,
    DisableSlotCmd = 10,
    AddressDeviceCard = 11,
    CoonfigEpCmd = 12,
    EvalCentextCmd = 13,
    RestEpCmd = 14,
    StopEpCmd = 15,
    SetTrDeqPtrCmd = 16,
    ResetDeviceCmd = 17,
    ForceEventCmd = 18,
    NegotiateBandwithCmd = 19,
    SetLatencyToleranceCmd = 20,
    GetPortBandwithCmd = 21,
    ForceHeaderCmd = 22,
    NoOpCmd = 23,
    GetExtendedPropCmd = 24,
    SetExtendedPropCmd = 25,
    TransferEvent = 32,
    CmdCompleteEvent = 33,
    PortStatChangeEvent = 34,
    BandwithReqEvent = 35,
    DoorbellEvent = 36,
    HcEvent = 37,
    DeviceNotifEvent = 38,
    MfindexWrapEvent = 39,
}

/// The list of TRB types that are allowed on the transfer ring
pub enum TransferRingTypes {
    Normal = 1,
    SetupStage = 2,
    DataStage = 3,
    StatusStage = 4,
    ISOCH = 5,
    Link = 6,
    EventData = 7,
    NoOp = 8,
}

/// The list of types that are allowed on the command ring
pub enum CommandRingTypes {
    Link = 6,
    EnableSlotCmd = 9,
    DisableSlotCmd = 10,
    AddressDeviceCard = 11,
    CoonfigEpCmd = 12,
    EvalCentextCmd = 13,
    RestEpCmd = 14,
    StopEpCmd = 15,
    SetTrDeqPtrCmd = 16,
    ResetDeviceCmd = 17,
    ForceEventCmd = 18,
    NegotiateBandwithCmd = 19,
    SetLatencyToleranceCmd = 20,
    GetPortBandwithCmd = 21,
    ForceHeaderCmd = 22,
    NoOpCmd = 23,
    GetExtendedPropCmd = 24,
    SetExtendedPropCmd = 25,
}

/// The list of types that are allowed on the event ring
pub enum EventRingType {
    TransferEvent = 32,
    CmdCompleteEvent,
    PortStatChangeEvent,
    BandwithReqEvent,
    DoorbellEvent,
    HcEvent,
    DeviceNotifEvent,
    MfindexWrapEvent,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq)]
/// A generic struct for Transfer Request Blocks (TRBs).
/// Precise setting and getting of specific fields for a given TRB shall be done
/// by the xHCI driver. See section 6.4 of the xHCI specs for more details.
pub struct TransferRequestBlock {
    pub parameters: u64,
    pub status: u32,
    pub control: u32,
}

pub type Trb = TransferRequestBlock;

impl TransferRequestBlock {
    /// Retrieves the TRB type from the control field in the TRB
    pub fn get_trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    /// Sets the TRB type field of the TRB to value.
    pub fn set_trb_type(&mut self, value: u32) {
        self.control = (self.control & !(0x3F << 10)) | (value << 10);
    }

    /// Retrieves the cycle bit from the control field of the TRB.
    pub fn get_cycle(&self) -> u32 {
        self.control & 1
    }

    /// Sets the cycle bit of the control field in the TRB to value.
    pub fn set_cycle(&mut self, value: u32) {
        self.control = (self.control & !1) | value;
    }

    /// Retrieves the evaluate next TRB bit from the control field of the TRB.
    pub fn get_ent(&self) -> u32 {
        (self.control >> 1) & 1
    }

    /// Sets the evaluate next TRB bit of the control field in the TRB to value.
    pub fn set_ent(&mut self, value: u32) {
        self.control = (self.control & !0x2) | (value << 1);
    }

    pub fn eq(&self, other: &TransferRequestBlock) -> bool {
        return (self.parameters == other.parameters) & (self.status == other.status) & (self.control == other.control);
    }
}

#[derive(Debug, Clone)]
pub enum RingType {
    Command,
    Transfer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Error codes for producer ring buffers.
pub enum ProducerRingError {
    /// Error indicating that an attempt to enqueue onto a ring that is full
    BufferFullError,
    /// Error indicating that there was an attempt to add a TRB with a type that does not belong on this ring type.
    /// For example, trying to enqueue a setup stage TRB onto a command ring or a no-op command onto a transfer ring.
    InvalidType,
    /// Error indicating that the address passed in is not aligned to 16
    UnalignedAddress,
    /// Error indicating that the size passed in is not aligned to 16
    UnalignedSize,
}

#[derive(Debug, Clone)]
/// Implements a producer ring buffer for use with the transfer and command rings associated with the xHCI.
pub struct ProducerRingBuffer {
    /// Pointer to the next TRB to be written to
    enqueue: *mut Trb,
    /// Pointer to the next TRB to read from
    dequeue: *mut Trb,
    /// The current Producer Cycle State (PCS)
    pcs: u8,
    /// The type of this ring, either Command, Transfer, or Event
    ring: RingType,
}

impl ProducerRingBuffer {
    /// Initializes and returns a new instance of a producer ring buffer or an error.
    ///
    /// # Arguments
    /// * `base_addr` - The base address of the ring buffer
    /// * `cycle_state` - What to initialize the PCS to
    /// * `ring_type` - The type of ring that this buffer will represent, either Command or Transfer
    /// * `size` - The size in bytes of the buffer pointed to by `base_addr`
    ///
    /// # Returns
    /// Returns a newly initialized `ProducerRingBuffer` on success, on error returns `Err(ProducerRingError)`.
    /// - `UnalignedAddress` if `base_addr` is not aligned to 16
    /// - `UnalignedSize` if `size` is not a multiple of 16
    ///
    /// # Safety
    /// - This function preforms a raw pointer access to initialize the Link TRB of the ring
    /// - Assumes that `base_addr` points to a valid memory region of at least `size` bytes
    pub fn new(
        base_addr: u64,
        cycle_state: u8,
        ring_type: RingType,
        size: isize,
    ) -> Result<Self, ProducerRingError> {
        // ensure that the base address is aligned to 16
        if base_addr % 16 != 0 {
            return Err(ProducerRingError::UnalignedAddress);
        }
        if size % 16 != 0 {
            return Err(ProducerRingError::UnalignedSize);
        }

        // initialize the link block at the end of this segment
        let num_blocks = size / 16;
        let enqueue = base_addr as *mut Trb;
        unsafe {
            let last_addr = enqueue.offset(num_blocks - 1);
            // sets the trb type to Link and the toggle cycle bit to 1
            (*last_addr).control = 0x1802;
            (*last_addr).parameters = base_addr;
        }
        Ok(ProducerRingBuffer {
            enqueue: base_addr as *mut Trb,
            dequeue: base_addr as *mut Trb,
            pcs: cycle_state,
            ring: ring_type,
        })
    }

    /// Sets the Enqueue field to the given address.
    ///
    /// # Arguments
    /// * `addr` - The address to set `enqueue` to
    pub fn set_enqueue(&mut self, addr: u64) -> Result<(), ProducerRingError> {
        if addr % 16 != 0 {
            return Err(ProducerRingError::UnalignedAddress);
        }

        self.enqueue = addr as *mut Trb;
        Ok(())
    }

    /// Sets the Dequeue field to the given address.
    ///
    /// # Arguments
    /// * `addr` - The address to set `dequeue` to
    ///
    pub fn set_dequeue(&mut self, addr: u64) -> Result<(), ProducerRingError> {
        if addr % 16 != 0 {
            return Err(ProducerRingError::UnalignedAddress);
        }

        self.dequeue = addr as *mut Trb;
        Ok(())
    }

    /// Checks if the block pointed to by enqueue is a link TRB
    unsafe fn is_enq_link(&self) -> bool {
        let next_trb = *self.enqueue;
        next_trb.get_trb_type() == TrbTypes::Link as u32
    }

    /// Checks if the block after the block enqueue is pointing to is a link TRB
    unsafe fn is_next_link(&self) -> bool {
        // gets the trb that is after the one currently pointed to
        let trb = *(self.enqueue.offset(1));
        trb.get_trb_type() == TrbTypes::Link as u32
    }

    /// Checks if the ring is full. Full is defined as if `enqueue` + 1 == `dequeue`, accounting for link TRB.
    ///
    /// # Returns
    /// True if the ring is full, false otherwise
    ///
    /// # Safety
    /// This functions uses unsafe actions on a raw pointer such as dereferencing it and adding an offset to it
    pub unsafe fn is_ring_full(&self) -> bool {
        // check if adding 1 to enqueue would make it point to a link trb
        let next_enq = if self.is_next_link() {
            // if so, set next_enq to the pointer stored in trb.parameters
            let next_trb = *(self.enqueue.offset(1));
            (next_trb.parameters & !0xF) as *mut Trb
        } else {
            // otherwise, just set next_enq to enqueue offsetted by one
            self.enqueue.offset(1)
        };
        self.dequeue == next_enq
    }

    /// Checks if the ring is empty. Empty is defined as if `enqueue` == `dequeue`.
    ///
    /// # Returns
    /// True if the ring is empty, false otherwise
    pub fn is_ring_empty(&self) -> bool {
        self.enqueue == self.dequeue
    }

    /// Moves the enqueue to point to the next TRB to enqueue at, following Link TRBs and toggling the cycle state if necessary
    unsafe fn increment_enqueue(&mut self) {
        self.enqueue = self.enqueue.offset(1);
        // if we are now pointing to a link change self.enqueue to the address in the parameters of the link block
        if self.is_enq_link() {
            let trb = *self.enqueue;
            // if the toggle cycle bit is 1 then toggle cycle_state
            if (trb.control & 0x2) == 2 {
                self.pcs ^= 1;
            }
            self.enqueue = (trb.parameters & !0xF) as *mut Trb;
        }
    }

    /// Queues a TRB onto the ring.
    ///
    /// # Arguments
    /// * `block` - The TRB data to be copied into the buffer
    ///
    /// # Returns
    /// Returns `Ok(())` on success, on error will return `Err(ProducerRingError)`
    /// - `InvalidType` if `block` has a TRB type that does not belong on this ring
    /// - `BufferFullError` if the ring is full
    ///
    /// # Safety
    /// - This function preforms a raw pointer update to copy `block`'s data onto the buffer
    /// - Increments `enqueue` to the next block, following any link TRBs
    pub unsafe fn enqueue(&mut self, mut block: Trb) -> Result<(), ProducerRingError> {
        // first make sure that we are trying to enqueue a TRB that belongs on this ring
        match self.ring {
            RingType::Command => {
                let trb_type = block.get_trb_type();
                if !(trb_type == 6 || matches!(trb_type, 9..=25)) {
                    return Err(ProducerRingError::InvalidType);
                }
            }
            RingType::Transfer => {
                let trb_type = block.get_trb_type();
                if !matches!(trb_type, 1..=8) {
                    return Err(ProducerRingError::InvalidType);
                }
            }
        }

        // If the ring is full then return enqueue error
        if self.is_ring_full() {
            return Err(ProducerRingError::BufferFullError);
        }

        // Write the current cycle state bit to the block
        block.control = (block.control & !1) | self.pcs as u32;

        let enqueue_addr = self.enqueue as u64;
        debug_println!("putting trb at address: {:X}", enqueue_addr);
        // copy the contents of block into enqueue
        // TODO: make sure this copies like I want it to
        // Should probally be volitale so the compiler dosent bork anything
        *self.enqueue = block;

        // increment the enqueue pointer
        self.increment_enqueue();
        Result::Ok(())
    }
}

#[derive(Debug, Clone)]
/// Implements an Event Ring Segment Table (ERST) for use by the xHC and the event ring.
struct EventRingSegmentTable {
    /// Pointer to the base of the ERST.
    base: *mut Trb,
    /// The current number of entries in this ERST.
    size: isize,
    /// The max number of entries this ERST can hold.
    max_size: isize,
    /// A BTreeMap that maps physical addresses to the corresponding virtual addresses mapped to them.
    address_map: BTreeMap<u64, u64>,
}

type Erst = EventRingSegmentTable;

impl EventRingSegmentTable {
    /// Gets the current number of entries in this ERST.
    fn get_size(&self) -> isize {
        self.size
    }

    /// Gets the entry at `index` and translates the physical address to the virtual address.
    unsafe fn get_entry(&self, index: isize) -> Trb {
        let block_addr = self.base.offset(index);
        let block = *block_addr;
        let param = block.parameters;
        let virt_addr = *self.address_map.get(&param).unwrap();
        Trb {
            parameters: virt_addr,
            status: block.status,
            control: block.control,
        }
    }

    /// If the table is not full, adds another segment to the table and returns true, returns false otherwise.
    unsafe fn add_entry(
        &mut self,
        segment_vbase: VirtAddr,
        segment_size: u32,
        segment_pbase: PhysAddr,
    ) -> bool {
        // if we are at the max size then return false
        if self.size == self.max_size {
            return false;
        }

        // Since this is a new entry add it to our map.
        let virt_address = segment_vbase.as_u64();
        let phys_address = segment_pbase.as_u64();
        self.address_map.insert(phys_address, virt_address);

        debug_println!("physical address: {:X}", phys_address);

        // create the entry
        let entry = Trb {
            parameters: phys_address & !0x3F,
            status: segment_size & 0xFFFF,
            control: 0,
        };

        // put the entry at the last index and then increment and return true
        *self.base.offset(self.size) = entry;
        self.size += 1;
        true
    }

    unsafe fn print_table(&self) {
        debug_println!("!!!!Printing ERST!!!!");
        debug_println!("size: {}", self.size);
        debug_println!("max size: {}", self.max_size);
        debug_println!("base: {:X}", self.base as u64);
        if self.size == 1 {
            let entry = *self.base.offset(0);
            let params = entry.parameters;
            let size = entry.status & 0xFFFF;
            debug_println!("index: 0\taddr: {:X}\tsize:{}", params, size);
        } else {
            for index in 0..self.size - 1 {
                let entry = *self.base.offset(index);
                let params = entry.parameters;
                let size = entry.status & 0xFFFF;
                debug_println!("index: {}\taddr: {:X}\tsize:{}", index, params, size);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Error codes for consumer Ring buffers.
pub enum EventRingError {
    /// Error indicating that an attempt to dequeue an empty ring.
    RingEmptyError,
    /// Error indicating that the size of a segment was not within the bounds of 16 - 4096
    SegmentSize,
    /// Error indicating that the ERST is full when a segment was attempted to be added.
    ERSTFull,
}


#[derive(Debug, Clone)]
/// Implements a consumer ring buffer for use with the event rings associated with the xHCI.
pub struct ConsumerRingBuffer {
    /// Pointer to the next TRB to dequeue.
    dequeue: *mut Trb,
    /// The current Consumer Cycle State (CCS).
    ccs: u8,
    /// The ERST associated with this Event Ring.
    erst: Erst,
    /// The index into the ERST of the segment that dequeue is currently pointing to.
    erst_count: isize,
    /// The highest index who's segment we have completely been through.
    count_visited: isize,
    /// The number of TRBs remaing in the current segment.
    ers_size: u32,
}

impl ConsumerRingBuffer {
    /// Initializes and returns a new instance of a consumer ring buffer or an error.
    ///
    /// # Arguments
    /// * `erst_base_addr` - The base address of the ERST for this event ring
    /// * `erst_max_size` - The max number of entries that the ERST can hold
    /// * `segment_vbase` - The base virtual address of the first segment that this event ring is initialized with
    /// * `segment_pbase` - The base physical address of the first segment that this event ring is initialized with
    /// * `segment_size` - The number of TRBs that the initial segment can hold
    ///
    /// # Returns
    /// Returns a newly initialized `ConsumerRingBuffer` on success, on error returns `Err(EventRingError)`.
    /// - `SegmentSize` if `segment_size` is not within 16 - 4096 (inclusive)
    ///
    /// # Safety
    /// - This function preforms a raw pointer write to add the first segment into the ERST
    /// - This function assumes that both `erst_base_addr` and `segment_base` points to a valid memory region
    /// - `segment_vbase` should be the virtual address that refers to the physical address of `segment_pbase`
    ///   that is zeroed out and has enough space for their respective sizes
    pub fn new(
        erst_base_addr: u64,
        erst_max_size: isize,
        segment_vbase: VirtAddr,
        segment_pbase: PhysAddr,
        segment_size: u32,
    ) -> Result<Self, EventRingError> {
        // first check that the segment is proper size
        if !(16..=4096).contains(&segment_size) {
            return Err(EventRingError::SegmentSize);
        }
        debug_println!("erst_base {:X}", erst_base_addr);
        debug_println!("segment virtual base {:X}", segment_vbase);

        // create the ERST for this ring
        let mut erst = EventRingSegmentTable {
            base: erst_base_addr as *mut Trb,
            size: 0,
            max_size: erst_max_size,
            address_map: BTreeMap::new(),
        };
        unsafe {
            erst.add_entry(segment_vbase, segment_size, segment_pbase);
        }

        // create the new buffer
        Ok(ConsumerRingBuffer {
            dequeue: segment_vbase.as_u64() as *mut Trb,
            ccs: 1,
            erst,
            erst_count: 0,
            count_visited: 0,
            ers_size: segment_size,
        })
    }

    /// Tries to add a new segment to the ERST.
    ///
    /// # Arguments
    /// * `segment_vbase` - The base virtual address of the segment that is being added
    /// * `segment_size` - The number of TRBs that this segment can hold
    /// * `segment_pbase` - The base physical address of the segment that is being added
    ///
    /// # Returns
    /// Returns `Ok(())` on success, on error returns `Err(EventRingError)`
    /// - `SegmentSize` if `segment_size` is not within the bounds of 16 - 4096 (inclusive)
    /// - `ERSTFull` if the ERST is already full and the new segment can not be added
    ///
    /// # Safety
    /// - This function preforms a raw pointer write to add the new segment into the ERST
    /// - This function assumes that `segment_vbase` points to a valid memory region of at least `segment_size * 16` bytes
    /// - `segment_vbase` should be the virtual address that refers to the physical address of `segment_pbase`
    ///
    /// # Notes
    /// Any calls to this method should be immediately followed by a write to the Event Ring Segment Table Size Register (ERSTSZ) with the new size.
    pub fn add_segment(
        &mut self,
        segment_vbase: VirtAddr,
        segment_size: u32,
        segment_pbase: PhysAddr,
    ) -> Result<(), EventRingError> {
        // check the segment size is within the bounds
        if !(16..=4096).contains(&segment_size) {
            return Err(EventRingError::SegmentSize);
        }

        // try to add the segment
        let result: bool;
        unsafe {
            result = self
                .erst
                .add_entry(segment_vbase, segment_size, segment_pbase);
        }

        // if failed, return erst full err
        if !result {
            return Err(EventRingError::ERSTFull);
        }
        Ok(())
    }

    /// Returns the value of the dequeue pointer.
    ///
    /// # Returns
    /// `self.dequeue` as a `u64`
    pub fn get_dequeue(&self) -> u64 {
        self.dequeue as u64
    }

    /// Tries to dequeue a TRB.
    ///
    /// # Returns
    /// Returns the TRB that is pointed to by `dequeue` on succes, on error returns `Err(EventRingError::RingEmptyError)`
    ///
    /// # Safety
    /// This function preforms a raw pointer access to read the TRB at `dequeue`.
    pub unsafe fn dequeue(&mut self) -> Result<Trb, EventRingError> {
        // first get the block and see if we own it
        let block: Trb;
        unsafe {
            block = core::ptr::read_volatile(self.dequeue);
        }

        // first check if we need to look at cycle bit or completion code
        if self.erst_count > self.count_visited {
            let completion_code = (block.status >> 24) & 0xFF;
            // if it is 0 then the ring is empty
            if completion_code == 0 {
                return Err(EventRingError::RingEmptyError);
            }
        } else if self.ccs as u32 != block.get_cycle() {
            // if the block's cycle bit does not match then we are at the enqueue pointer meaning that buffer is empty
            return Err(EventRingError::RingEmptyError);
        }

        // move the dequeue pointer
        self.move_dequeue();
        Ok(block)
    }

    /// Moves `dequeue` to the next TRB to be dequeued skipping unvisited segments and looping and whatnot.
    unsafe fn move_dequeue(&mut self) {
        if self.ers_size == 1 {
            // need to go to a new segment, if this is a new segment increment count visited
            if self.erst_count > self.count_visited {
                self.count_visited = self.erst_count;
            }

            // now check to see if we need to loop back to the beginning
            self.erst_count += 1;
            if self.erst_count == self.erst.get_size() {
                // toggle ccs and set count to 0
                self.ccs ^= 1;
                self.erst_count = 0;
            }

            // get the block at index count
            let mut entry = self.erst.get_entry(self.erst_count);
            // this may be a new segment that we have not seen
            if self.erst_count > self.count_visited {
                // we have not been in this segment yet, check if the xHC has written in it
                let first_block = *(entry.parameters as *mut Trb);
                // get the completion code to check for 0
                let completion_code = (first_block.status >> 24) & 0xFF;
                if completion_code == 0 {
                    // the xHC has not written in this segment yet so skip it
                    self.ccs ^= 1;
                    self.erst_count = 0;
                    entry = self.erst.get_entry(self.erst_count);
                }
            }

            // set dequeue and size
            self.dequeue = entry.parameters as *mut Trb;
            self.ers_size = entry.status & 0xFFFF;
        } else {
            // there are still blocks in this segment so just move things
            self.ers_size -= 1;
            self.dequeue = self.dequeue.offset(1);
        }
    }

    /// Checks to see if the event ring is empty
    ///
    /// # Returns
    /// True if the TRB being pointed to by `dequeue` is not owned by the consumer.
    ///
    /// # Safety
    /// This function preforms a raw pointer read to access the TRB that is being pointed to.
    pub unsafe fn is_empty(&self) -> bool {
        // first get the block
        let block = core::ptr::read_volatile(self.dequeue);
        let parameters = block.parameters;
        let status = block.status;
        let control = block.control;
        debug_println!("params: {:X}", parameters);
        debug_println!("status: {:X}", status);
        debug_println!("control: {:X}", control);

        // see if we need to check the completion code or cycle bit
        if self.erst_count > self.count_visited {
            let completion_code = (block.status >> 24) & 0xFF;
            // if 0 then empty
            return completion_code == 0;
        }

        debug_println!("cycle bit: {}", block.get_cycle());

        block.get_cycle() != self.ccs as u32
    }

    /// Prints event rung
    ///
    /// # Safety
    /// TODO
    pub unsafe fn print_ring(&self) {
        debug_println!("======PRINTING EVENT RING======");
        debug_println!("dequeue ptr: {:X}", self.dequeue as u64);
        debug_println!("ccs: {}", self.ccs);
        self.erst.print_table();
        debug_println!("erst index: {}", self.erst_count);
        debug_println!("ers size: {}", self.ers_size);
        debug_println!("index visited: {}", self.count_visited);
        debug_println!("===============================");
    }
}

#[cfg(test)]
mod test {
    use x86_64::{addr::VirtAddr, structures::paging::Mapper};
    use alloc::format;

    use super::{
        ring_buffer::{ProducerRingBuffer, RingType, Trb, TrbTypes},
        *,
    };
    use crate::{
        devices::xhci::ring_buffer::{CommandRingTypes, ConsumerRingBuffer, EventRingError, EventRingType, ProducerRingError, TransferRequestBlock},
        memory::{
            frame_allocator::dealloc_frame,
            paging::{create_mapping, remove_mapped_frame},
            MAPPER,
        },
    };

    #[test_case]
    fn prod_ring_buffer_init() {
        // first get a page and zero init it
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // call the new function
        let base_addr = page.start_address().as_u64();
        let size = page.size() as isize;
        let _cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size);

        // make sure the link trb is set correctly
        let mut trb_ptr = base_addr as *const Trb;
        let trb: Trb;
        unsafe {
            trb_ptr = trb_ptr.offset(size / 16 - 1);
            trb = *trb_ptr;
        }

        let params = trb.parameters;
        let status = trb.status;
        let control = trb.control;

        assert_eq!(params, base_addr);
        assert_eq!(status, 0);
        assert_eq!(control, 0x1802);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn prod_ring_buffer_enqueue() {
        // initialize a ring buffer we can enqueue onto
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // call the new function
        let base_addr = page.start_address().as_u64();
        let size = page.size() as isize;
        let mut cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size)
            .expect("Error initializing producer ring");

        // create a block to queue
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_trb_type(TrbTypes::NoOpCmd as u32);

        // enqueue the block
        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        let ring_base = base_addr as *mut Trb;
        let mut trb: Trb;
        unsafe {
            trb = *ring_base;
        }
        assert_eq!(trb.get_trb_type(), TrbTypes::NoOpCmd as u32);
        assert_eq!(trb.get_cycle(), 1);

        // enqueue another block
        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
            trb = *(ring_base.offset(1));
        }
        assert_eq!(trb.get_trb_type(), TrbTypes::NoOpCmd as u32);
        assert_eq!(trb.get_cycle(), 1);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn prod_ring_buffer_helpers() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // create a small ring buffer
        let base_addr = page.start_address().as_u64();
        let size: isize = 64;
        let mut cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size)
            .expect("Error initializing producer ring");

        // test is empty and is full funcs
        let mut result = cmd_ring.is_ring_empty();
        assert_eq!(result, true);

        unsafe {
            result = cmd_ring.is_ring_full();
        }

        assert_eq!(result, false);

        // create a no-op cmd to queue a couple of times
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_trb_type(TrbTypes::NoOpCmd as u32);

        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        // both empty and true should be false
        result = cmd_ring.is_ring_empty();
        assert_eq!(result, false);

        unsafe {
            result = cmd_ring.is_ring_full();
            assert_eq!(result, false);
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        // empty should be false and full should be true
        result = cmd_ring.is_ring_empty();
        assert_eq!(result, false);

        unsafe {
            result = cmd_ring.is_ring_full();
        }
        assert_eq!(result, true);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn prod_ring_buffer_enqueue_accross_segment() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // create a small ring buffer
        let base_addr = page.start_address().as_u64();
        let size: isize = 64;
        let mut cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size)
            .expect("Error initializing producer ring");

        // create our no op cmd
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_trb_type(TrbTypes::NoOpCmd as u32);

        // queue it up so we can test that later the cycle bit gets correctly written
        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }
        // move the enqueue to the last block before the end and then the dequeue over one
        cmd_ring
            .set_enqueue(base_addr + 32)
            .expect("set_enqueue error");
        cmd_ring
            .set_dequeue(base_addr + 16)
            .expect("set_dequeue error");

        // now try to enqueue
        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        // ring should be considered full now
        unsafe {
            assert!(cmd_ring.is_ring_full());
        }

        // now move dequeue so we can test that enqueue properly writes the cycle bit to 0
        cmd_ring
            .set_dequeue(base_addr + 32)
            .expect("set_dequeue error");

        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        // now lettuce check that the cycle bit of the very first block is 0
        let trb_ptr = base_addr as *const Trb;
        let trb: Trb;
        unsafe {
            trb = *trb_ptr;
        }

        assert_eq!(trb.get_cycle(), 0);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn consumer_ring_buffer_init() {
        // first get pages for the ERST and first segment
        let mut mapper: spin::MutexGuard<'_, OffsetPageTable<'_>> = MAPPER.lock();
        let erst_frame = alloc_frame().unwrap();
        let erst_page: Page =
            Page::containing_address(mapper.phys_offset() + erst_frame.start_address().as_u64());
        let segment_frame = alloc_frame().unwrap();
        let segment_page: Page =
            Page::containing_address(mapper.phys_offset() + segment_frame.start_address().as_u64());

        let fake_device_frame = alloc_frame().unwrap();
        let fake_device_page: Page = Page::containing_address(
            mapper.phys_offset() + fake_device_frame.start_address().as_u64(),
        );
        let segment_frame_addr = segment_frame.start_address();

        let erst_entry_size = 16 as isize;

        mmio::zero_out_page(erst_page);
        mmio::zero_out_page(segment_page);
        // call the initialization function
        let erst_address = erst_page.start_address().as_u64();
        let segment_address = segment_page.start_address().as_u64();
        let page_size = erst_page.size() as isize;
        let event_ring = ConsumerRingBuffer::new(
            erst_address,
            page_size / erst_entry_size,
            segment_page.start_address(),
            segment_frame_addr,
            (page_size / size_of::<TransferRequestBlock>() as isize) as u32,
        )
        .expect("Error initializing consumer ring");

        // Ensure the RingBuffer thinks that it is empty
        unsafe {
            assert_eq!(true, event_ring.is_empty());
        }

        // verify that the ERST was properly initialized

        // check that the first TRB's worth of the ERST contains the correct information about the segment
        let mut trb_ptr = erst_address as *const Trb;
        let mut trb;
        unsafe {
            trb = *trb_ptr;
        }

        // added due to "unaligned padded struct field" error, probably not actually a good solution, I'd like
        // to know how we were unaligned
        let mut parameters = trb.parameters;
        let mut status = trb.status;
        let mut control = trb.control;

        assert_eq!(parameters, segment_frame_addr.as_u64() & !0x3F);
        assert_eq!(
            status,
            (page_size / size_of::<TransferRequestBlock>() as isize) as u32 & 0xFFFF
        );
        assert_eq!(control, 0);

        // check that the rest of the TRB's worth of the ERST is still zeroed
        for _ in 1..(page_size / erst_entry_size) {
            unsafe {
                trb_ptr = trb_ptr.offset(1);
                trb = *trb_ptr;
            }

            parameters = trb.parameters;
            status = trb.status;
            control = trb.control;

            assert_eq!(parameters, 0);
            assert_eq!(status, 0);
            assert_eq!(control, 0);
        }

        // check that the data segment remains untouched
        trb_ptr = segment_address as *const Trb;
        unsafe {
            trb = *trb_ptr;
        }

        for _ in 1..(page_size / erst_entry_size) {
            parameters = trb.parameters;
            status = trb.status;
            control = trb.control;

            assert_eq!(parameters, 0);
            assert_eq!(status, 0);
            assert_eq!(control, 0);

            unsafe {
                assert_eq!(size_of::<TransferRequestBlock>() as isize, 16);
                trb_ptr = trb_ptr.offset(1);
                trb = *trb_ptr;
            }
        }
        dealloc_frame(erst_frame);
        dealloc_frame(segment_frame);
        dealloc_frame(fake_device_frame);
    }

    #[test_case]
    fn consumer_ring_buffer_single_segment_dequeue() {
        // some constants
        const SEGMENT_ENTRIES: u32 = 16;
        const ERST_ENTRY_SIZE: isize = 16;

        // get pages for the ERST and data segment
        let mut mapper: spin::MutexGuard<'_, OffsetPageTable<'_>> = MAPPER.lock();

        let erst_page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let segment_page: Page = Page::containing_address(VirtAddr::new(0x600000000));
        create_mapping(erst_page, &mut *mapper, None);
        create_mapping(segment_page, &mut *mapper, None);

        let page_size = erst_page.size() as isize;

        let segment_frame = mapper
            .translate_page(segment_page)
            .expect("error translating page");
        let segment_paddr = segment_frame.start_address();

        // zero the pages we grabbed
        mmio::zero_out_page(erst_page);
        mmio::zero_out_page(segment_page);

        // call the initialization function
        let erst_address = erst_page.start_address().as_u64();
        let segment_vaddr = segment_page.start_address().as_u64();
        let mut event_ring = ConsumerRingBuffer::new(
            erst_address,
            page_size / ERST_ENTRY_SIZE,
            segment_page.start_address(),
            segment_paddr,
            SEGMENT_ENTRIES,
        ).expect("Error initializing consumer ring");

        // test a read on an empty RingBuffer
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // write a dummy TRB to the current head of the data segment
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_cycle(1);
        cmd.set_trb_type(EventRingType::CmdCompleteEvent as u32);
        cmd.status |= 0xFF << 24;

        let mut trb_ptr = segment_vaddr as *mut Trb;
        unsafe {
            *trb_ptr = cmd;
            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
        }

        // make sure that the ring thinks it is empty again
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // add a couple of TRBs and then read them
        unsafe {
            trb_ptr = trb_ptr.offset(1);
            *trb_ptr = cmd;
            trb_ptr = trb_ptr.offset(1);
            *trb_ptr = cmd;

            event_ring.print_ring();

            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
        }

        // fill in the rest of the TRB: Entries 4-16
        unsafe {
            for i in 4..SEGMENT_ENTRIES+1 {
                trb_ptr = trb_ptr.offset(1);
                *trb_ptr = cmd;
            }

            for i in 4..SEGMENT_ENTRIES+1 {
                assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
            }
        }

        // make sure that the ring thinks it is empty again
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // make sure we properly wrap around
        cmd.set_cycle(0);
        trb_ptr = segment_vaddr as *mut Trb;
        unsafe {
            *trb_ptr = cmd;

            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
        }

        // make sure that the ring thinks it is empty again
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        remove_mapped_frame(erst_page, &mut *mapper);
        remove_mapped_frame(segment_page, &mut *mapper);
    }

    #[test_case]
    fn consumer_ring_add_segment() {
        // some constants
        const SEGMENT_ENTRIES: u32 = 16;
        const ERST_ENTRY_SIZE: isize = 16;

        // get pages for the ERST and data segment
        let mut mapper: spin::MutexGuard<'_, OffsetPageTable<'_>> = MAPPER.lock();

        let erst_page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let first_segment_page: Page = Page::containing_address(VirtAddr::new(0x600000000));
        let second_segment_page: Page = Page::containing_address(VirtAddr::new(0x700000000));
        create_mapping(erst_page, &mut *mapper, None);
        create_mapping(first_segment_page, &mut *mapper, None);
        create_mapping(second_segment_page, &mut *mapper, None);

        let page_size = erst_page.size() as isize;

        let first_segment_frame = mapper
            .translate_page(first_segment_page)
            .expect("error translating page");
        let second_segment_frame = mapper
            .translate_page(second_segment_page)
            .expect("error translating page");
        let first_segment_paddr = first_segment_frame.start_address();
        let second_segment_paddr = second_segment_frame.start_address();

        // zero the pages we grabbed
        mmio::zero_out_page(erst_page);
        mmio::zero_out_page(first_segment_page);
        mmio::zero_out_page(second_segment_page);

        // call the initialization function
        let erst_address = erst_page.start_address().as_u64();
        let first_segment_vaddr = first_segment_page.start_address().as_u64();
        let second_segment_vaddr = second_segment_page.start_address().as_u64();
        let mut event_ring = ConsumerRingBuffer::new(
            erst_address,
            page_size / ERST_ENTRY_SIZE,
            first_segment_page.start_address(),
            first_segment_paddr,
            SEGMENT_ENTRIES,
        ).expect("Error initializing consumer ring");

        event_ring.add_segment(second_segment_page.start_address(), SEGMENT_ENTRIES, second_segment_paddr).expect("Error adding new segment to ring");

        // check the state of the ERST

        // check that the first two TRB's worth of the ERST contains the correct information about the segments
        let mut trb_ptr = erst_address as *const Trb;
        let mut trb;
        unsafe {
            trb = *trb_ptr;
        }

        let mut parameters = trb.parameters;
        let mut status = trb.status;
        let mut control = trb.control;

        assert_eq!(parameters, first_segment_paddr.as_u64() & !0x3F);
        assert_eq!(
            status,
            SEGMENT_ENTRIES as u32 & 0xFFFF
        );
        assert_eq!(control, 0);

        unsafe {
            trb_ptr = trb_ptr.offset(1);
            trb = *trb_ptr;
        }

        parameters = trb.parameters;
        status = trb.status;
        control = trb.control;

        assert_eq!(parameters, second_segment_paddr.as_u64() & !0x3F);
        assert_eq!(
            status,
            SEGMENT_ENTRIES as u32 & 0xFFFF
        );
        assert_eq!(control, 0);

        // check that the rest of the TRB's worth of the ERST is still zeroed
        for _ in 2..(page_size / ERST_ENTRY_SIZE) {
            unsafe {
                trb_ptr = trb_ptr.offset(1);
                trb = *trb_ptr;
            }

            parameters = trb.parameters;
            status = trb.status;
            control = trb.control;

            assert_eq!(parameters, 0);
            assert_eq!(status, 0);
            assert_eq!(control, 0);
        }

        remove_mapped_frame(erst_page, &mut *mapper);
        remove_mapped_frame(first_segment_page, &mut *mapper);
        remove_mapped_frame(second_segment_page, &mut *mapper);
    }
    
    #[test_case]
    fn consumer_ring_buffer_multi_segment_dequeue() {
        // some constants
        const SEGMENT_ENTRIES: u32 = 16;
        const ERST_ENTRY_SIZE: isize = 16;

        // get pages for the ERST and data segment
        let mut mapper: spin::MutexGuard<'_, OffsetPageTable<'_>> = MAPPER.lock();

        let erst_page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let first_segment_page: Page = Page::containing_address(VirtAddr::new(0x600000000));
        let second_segment_page: Page = Page::containing_address(VirtAddr::new(0x700000000));
        create_mapping(erst_page, &mut *mapper, None);
        create_mapping(first_segment_page, &mut *mapper, None);
        create_mapping(second_segment_page, &mut *mapper, None);

        let page_size = erst_page.size() as isize;

        let first_segment_frame = mapper
            .translate_page(first_segment_page)
            .expect("error translating page");
        let second_segment_frame = mapper
            .translate_page(second_segment_page)
            .expect("error translating page");
        let first_segment_paddr = first_segment_frame.start_address();
        let second_segment_paddr = second_segment_frame.start_address();

        // zero the pages we grabbed
        mmio::zero_out_page(erst_page);
        mmio::zero_out_page(first_segment_page);
        mmio::zero_out_page(second_segment_page);

        // call the initialization function
        let erst_address = erst_page.start_address().as_u64();
        let first_segment_vaddr = first_segment_page.start_address().as_u64();
        let second_segment_vaddr = second_segment_page.start_address().as_u64();
        let mut event_ring = ConsumerRingBuffer::new(
            erst_address,
            page_size / ERST_ENTRY_SIZE,
            first_segment_page.start_address(),
            first_segment_paddr,
            SEGMENT_ENTRIES,
        ).expect("Error initializing consumer ring");

        event_ring.add_segment(second_segment_page.start_address(), SEGMENT_ENTRIES, second_segment_paddr);

        // test a read on an empty RingBuffer
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // make sure that we actually check the second segment
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_cycle(1);
        cmd.set_trb_type(EventRingType::CmdCompleteEvent as u32);
        cmd.status |= 0xFF << 24;

        let mut trb_ptr = first_segment_vaddr as *mut Trb;

        // fill the first segment fully
        for i in 1..SEGMENT_ENTRIES+1 {
            unsafe {
                *trb_ptr = cmd;
                trb_ptr = trb_ptr.offset(1);
            }
        }

        // read the entire first segment
        for i in 1..SEGMENT_ENTRIES+1 {
            unsafe {
                assert_eq!(event_ring.dequeue().expect(&format!("dequeue error for TRB {i}")), cmd);
            }
        }

        // ensure the ring is empty
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // try to read from the second segment and sanity check that we still realize we're empty
        unsafe {
            trb_ptr = second_segment_vaddr as *mut Trb;
            *trb_ptr = cmd;

            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // fill the rest of the second segment and then dequeue it, then ensure we read as empty
        for i in 2..SEGMENT_ENTRIES+1 {
            unsafe {
                *trb_ptr = cmd;
                trb_ptr = trb_ptr.offset(1);
            }
        }
        for i in 2..SEGMENT_ENTRIES+1 {
            unsafe {
                assert_eq!(event_ring.dequeue().expect(&format!("dequeue error for TRB {i}")), cmd);
            }
        }
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // make sure we wrap back around to the first segment with cycle set to zero, then read as empty
        cmd.set_cycle(0);
        trb_ptr = first_segment_vaddr as *mut Trb;
        unsafe {
            *trb_ptr = cmd;

            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // go back around one time, the specific cycle bit shouldn't matter, but why not
        for i in 2..SEGMENT_ENTRIES+1 {
            unsafe {
                *trb_ptr = cmd;
                trb_ptr = trb_ptr.offset(1);
            }
        }
        for i in 2..SEGMENT_ENTRIES+1 {
            unsafe {
                assert_eq!(event_ring.dequeue().expect(&format!("dequeue error for TRB {i}")), cmd);
            }
        }
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        trb_ptr = second_segment_vaddr as *mut Trb;
        for i in 1..SEGMENT_ENTRIES+1 {
            unsafe {
                *trb_ptr = cmd;
                trb_ptr = trb_ptr.offset(1);
            }
        }
        for i in 1..SEGMENT_ENTRIES+1 {
            unsafe {
                assert_eq!(event_ring.dequeue().expect(&format!("dequeue error for TRB {i}")), cmd);
            }
        }
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        cmd.set_cycle(1);
        trb_ptr = first_segment_vaddr as *mut Trb;
        unsafe {
            *trb_ptr = cmd;

            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }
        
        remove_mapped_frame(erst_page, &mut *mapper);
        remove_mapped_frame(first_segment_page, &mut *mapper);
        remove_mapped_frame(second_segment_page, &mut *mapper);
    }

    #[test_case]
    fn consumer_ring_buffer_multi_segment_skip() {
        // some constants
        const SEGMENT_ENTRIES: u32 = 16;
        const ERST_ENTRY_SIZE: isize = 16;

        // get pages for the ERST and data segment
        let mut mapper: spin::MutexGuard<'_, OffsetPageTable<'_>> = MAPPER.lock();

        let erst_page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let first_segment_page: Page = Page::containing_address(VirtAddr::new(0x600000000));
        let second_segment_page: Page = Page::containing_address(VirtAddr::new(0x700000000));
        create_mapping(erst_page, &mut *mapper, None);
        create_mapping(first_segment_page, &mut *mapper, None);
        create_mapping(second_segment_page, &mut *mapper, None);

        let page_size = erst_page.size() as isize;

        let first_segment_frame = mapper
            .translate_page(first_segment_page)
            .expect("error translating page");
        let second_segment_frame = mapper
            .translate_page(second_segment_page)
            .expect("error translating page");
        let first_segment_paddr = first_segment_frame.start_address();
        let second_segment_paddr = second_segment_frame.start_address();

        // zero the pages we grabbed
        mmio::zero_out_page(erst_page);
        mmio::zero_out_page(first_segment_page);
        mmio::zero_out_page(second_segment_page);

        // call the initialization function
        let erst_address = erst_page.start_address().as_u64();
        let first_segment_vaddr = first_segment_page.start_address().as_u64();
        let second_segment_vaddr = second_segment_page.start_address().as_u64();
        let mut event_ring = ConsumerRingBuffer::new(
            erst_address,
            page_size / ERST_ENTRY_SIZE,
            first_segment_page.start_address(),
            first_segment_paddr,
            SEGMENT_ENTRIES,
        ).expect("Error initializing consumer ring");

        event_ring.add_segment(second_segment_page.start_address(), SEGMENT_ENTRIES, second_segment_paddr);

        // test a read on an empty RingBuffer
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // make sure that we actually check the second segment
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_cycle(1);
        cmd.set_trb_type(EventRingType::CmdCompleteEvent as u32);
        cmd.status |= 0xFF << 24;

        let mut trb_ptr = first_segment_vaddr as *mut Trb;

        // fill the first segment fully
        for i in 1..SEGMENT_ENTRIES+1 {
            unsafe {
                *trb_ptr = cmd;
                trb_ptr = trb_ptr.offset(1);
            }
        }

        // read the entire first segment
        for i in 1..SEGMENT_ENTRIES+1 {
            unsafe {
                assert_eq!(event_ring.dequeue().expect(&format!("dequeue error for TRB {i}")), cmd);
            }
        }

        // ensure the ring is empty
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // skip the second segment and make sure the consumer follows suite
        cmd.set_cycle(0);
        trb_ptr = first_segment_vaddr as *mut Trb;
        unsafe {
            *trb_ptr = cmd;

            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        // go back around one time, the specific cycle bit shouldn't matter, but why not
        for i in 2..SEGMENT_ENTRIES+1 {
            unsafe {
                *trb_ptr = cmd;
                trb_ptr = trb_ptr.offset(1);
            }
        }
        for i in 2..SEGMENT_ENTRIES+1 {
            unsafe {
                assert_eq!(event_ring.dequeue().expect(&format!("dequeue error for TRB {i}")), cmd);
            }
        }
        unsafe {
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }

        cmd.set_cycle(1);
        trb_ptr = first_segment_vaddr as *mut Trb;
        unsafe {
            *trb_ptr = cmd;

            assert_eq!(event_ring.dequeue().expect("dequeue error"), cmd);
            assert_eq!(event_ring.dequeue().unwrap_err(), EventRingError::RingEmptyError);
        }
        
        remove_mapped_frame(erst_page, &mut *mapper);
        remove_mapped_frame(first_segment_page, &mut *mapper);
        remove_mapped_frame(second_segment_page, &mut *mapper);
    }
}