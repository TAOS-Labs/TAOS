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
#[derive(Debug, Clone, Copy)]
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
    pub fn new(base_addr: u64, cycle_state: u8, ring_type: RingType, size: isize) -> Result<Self, ProducerRingError> {
        // ensure that the base address is aligned to 16
        if base_addr % 16 != 0 {
            return Err(ProducerRingError::UnalignedAddress)
        }
        if size % 16 != 0 {
            return Err(ProducerRingError::UnalignedSize)
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
            return Err(ProducerRingError::UnalignedAddress)
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
            return Err(ProducerRingError::UnalignedAddress)
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
            block = *self.dequeue;
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
        let block = *self.dequeue;
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
