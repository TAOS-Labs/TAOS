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
    Reserved,
    Normal,
    SetupStage,
    DataStage,
    StatusStage,
    ISOCH,
    Link,
    EventData,
    NoOp,
}

/// The list of types that are allowed on the command ring
pub enum CommandRingTypes {
    Link = 6,
    EnableSlotCmd = 9,
    DisableSlotCmd,
    AddressDeviceCard,
    CoonfigEpCmd,
    EvalCentextCmd,
    RestEpCmd,
    StopEpCmd,
    SetTrDeqPtrCmd,
    ResetDeviceCmd,
    ForceEventCmd,
    NegotiateBandwithCmd,
    SetLatencyToleranceCmd,
    GetPortBandwithCmd,
    ForceHeaderCmd,
    NoOpCmd,
    GetExtendedPropCmd,
    SetExtendedPropCmd,
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
        self.control = (self.control & !0x2) | value << 1;
    }
}

#[derive(Debug, Clone)]
pub enum RingType {
    Command,
    Event,
    Transfer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Error codes for ring buffers
pub enum RingBufferError {
    /// Error indicating that an attempt to enqueue onto a ring that is full
    BufferFullError,
    /// Error indicating that an attempt to dequeue from a ring that is empty
    BufferEmptyError,
    /// Error indicating that an improper action was taken on a ring.
    /// For example, dequeue on a command or transfer ring or enqueue on an event ring.
    InvalidType,
    /// Error indicating that the address passed in is not aligned to 16
    UnalignedAddress,
    /// Error indicating that the size passed in is not aligned to 16
    UnalignedSize,
}

#[derive(Debug, Clone)]
/// Implements a ring buffer for use with the different rings associated with
/// the xHCI.
pub struct RingBuffer {
    /// Pointer to the next TRB to be written to
    enqueue: *mut Trb,
    /// Pointer to the next TRB to read from
    dequeue: *mut Trb,
    /// The state of the cycle bit, represents both the Producer Cycle State (PCS) and the Consumer Cycle State (CCS)
    cycle_state: u8,
    /// The type of this ring, either Command, Transfer, or Event
    ring: RingType,
}

impl RingBuffer {
    /// Initializes and returns a new instance of a ring buffer or an error.
    ///
    /// # Arguments
    /// * `base_addr` - The base address of the ring buffer
    /// * `cycle_state` - What to initialize PCS/CCS to
    /// * `ring_type` - The type of ring that this buffer will represent, either Command, Transfer or Event
    /// * `size` - The size of the buffer pointed to by `base_addr`
    ///
    /// # Returns
    /// Returns a newly initialize `RingBuffer` on success, on error returns `Err(RingBufferError)`.
    /// - `UnalignedAddress` if `base_addr` is not aligned to 16
    /// - `UnalignedSize` if `size` is not a multiple of 16
    ///
    /// # Safety
    /// - This function preforms a raw pointer access to initialize the Link TRB of the RingBuffer
    /// - Assumes that `base_addr` points to a valid memory region of at least `size` bytes
    pub fn new(
        base_addr: u64,
        cycle_state: u8,
        ring_type: RingType,
        size: isize,
    ) -> Result<Self, RingBufferError> {
        // ensure that the base address is aligned to 16
        if base_addr % 16 != 0 {
            return Err(RingBufferError::UnalignedAddress);
        }
        // make sure that size is a multiple of 16
        if size % 16 != 0 {
            return Err(RingBufferError::UnalignedSize);
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
        Ok(RingBuffer {
            enqueue: base_addr as *mut Trb,
            dequeue: base_addr as *mut Trb,
            cycle_state,
            ring: ring_type,
        })
    }

    /// Sets the Enqueue field to the given address.
    ///
    /// # Arguments
    /// * `addr` - The address to set `enqueue` to
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(RingBufferError::UnalignedAddress)` if `addr` is not aligned to 16
    pub fn set_enqueue(&mut self, addr: u64) -> Result<(), RingBufferError> {
        if addr % 16 != 0 {
            return Err(RingBufferError::UnalignedAddress);
        }

        self.enqueue = addr as *mut Trb;
        Ok(())
    }

    /// Sets the Dequeue field to the given address.
    ///
    /// # Arguments
    /// * `addr` - The address to set `dequeue` to
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(RingBufferError::UnalignedAddress)` if `addr` is not aligned to 16
    pub fn set_dequeue(&mut self, addr: u64) -> Result<(), RingBufferError> {
        if addr % 16 != 0 {
            return Err(RingBufferError::UnalignedAddress);
        }

        self.dequeue = addr as *mut Trb;
        Ok(())
    }

    unsafe fn is_enq_link(&self) -> bool {
        let next_trb = *self.enqueue;
        next_trb.get_trb_type() == TrbTypes::Link as u32
    }

    unsafe fn is_deq_link(&self) -> bool {
        let next_trb = *self.dequeue;
        next_trb.get_trb_type() == TrbTypes::Link as u32
    }

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

    unsafe fn increment_enqueue(&mut self) {
        self.enqueue = self.enqueue.offset(1);
        // if we are now pointing to a link change self.enqueue to the address in the parameters of the link block
        if self.is_enq_link() {
            let trb = *self.enqueue;
            // if the toggle cycle bit is 1 then toggle cycle_state
            if (trb.control & 0x2) == 2 {
                self.cycle_state ^= 1;
            }
            self.enqueue = (trb.parameters & !0xF) as *mut Trb;
        }
    }

    unsafe fn increment_dequeue(&mut self) {
        self.dequeue = self.dequeue.offset(1);
        // if we are now pointing to a link change dequeue to the address in the link block
        if self.is_deq_link() {
            let trb = *self.dequeue;
            // if the toggle cycle bit is 1 then toggle cycle_state
            if (trb.control & 0x2) == 2 {
                self.cycle_state ^= 1;
            }
            self.dequeue = (trb.parameters & !0xF) as *mut Trb;
        }
    }

    /// Queues a TRB onto the ring.
    ///
    /// # Arguments
    /// * `block` - The TRB data to be copied into the buffer
    ///
    /// # Returns
    /// returns `Ok(())` on success, on error will return `Err(RingBufferError)`
    /// - `InvalidType` if this ring is an Event ring
    /// - `BufferFullError` if the ring is full
    ///
    /// # Safety
    /// - This function preforms a raw pointer update to copy `block`'s data onto the buffer
    /// - Increments `enqueue` to the next block, skipping any link TRBs
    pub unsafe fn enqueue(&mut self, mut block: Trb) -> Result<(), RingBufferError> {
        // If the ring type isnt command or transfer then return invalid type error
        if let RingType::Event = self.ring {
            return Err(RingBufferError::InvalidType);
        }

        // If the ring is full then return enqueue error
        if self.is_ring_full() {
            return Err(RingBufferError::BufferFullError);
        }

        // Write the current cycle state bit to the block
        block.control = (block.control & !1) | self.cycle_state as u32;

        // copy the contents of block into enqueue
        // TODO: make sure this copies like I want it to
        *self.enqueue = block;

        // increment the enqueue pointer
        self.increment_enqueue();
        Result::Ok(())
    }

    /// Dequeues a TRB from the ring.
    ///
    /// # Returns
    /// Returns the next block to be dequeued on success, on error returns `Err(RingBufferError)`
    /// - `InvalidType` if this ring is not an Event ring
    /// - `BufferEmptyError` if the ring is empty
    ///
    /// # Safety
    /// - Preforms a dereference on a raw pointer to read the block
    /// - Increments `dequeue` to the next block, skipping any link TRBs
    pub unsafe fn dequeue(&mut self) -> Result<Trb, RingBufferError> {
        // if the ring isnt event then return invalid type error
        match self.ring {
            RingType::Event => {}
            _ => return Err(RingBufferError::InvalidType),
        }

        // If the ring is empty then reurn dequeue error
        if self.is_ring_empty() {
            return Err(RingBufferError::BufferEmptyError);
        }

        // get the block
        let block = *self.dequeue;

        // increment the dequeue pointer
        self.increment_dequeue();

        Result::Ok(block)
    }
}

struct EventRingSegmentTable {
    // the base of the table
    base: *mut Trb,
    // the size of the table in number of entries
    size: isize,
}

type Erst = EventRingSegmentTable;

impl EventRingSegmentTable {
    // returns the number of entries in this table
    fn get_size(&self) -> isize {
        self.size
    }

    // returns the entry at the index
    unsafe fn get_entry(&self, index: isize) -> Trb {
        let block_addr = self.base.offset(index);
        *block_addr
    }

    unsafe fn add_entry(&mut self, segment_base: u64, segment_size: u32) {
        let entry = Trb {
            parameters: segment_base & !0xF,
            status: segment_size & 0xFFFF,
            control: 0
        };

        *self.base.offset(self.size) = entry;
    }
}

pub enum EventRingError {
    RingEmptyError,
    SegmentSize,
}

pub struct ConsumerRingBuffer {
    // the current dequeue pointer
    dequeue: *mut Trb,
    // the current ccs
    ccs: u8,
    // the erst for this event ring
    erst: Erst,
    // the current index into the erst that we are working in
    erst_count: isize,
    // the number of entries remaining in the current segment
    ers_size: u32,
}

impl ConsumerRingBuffer {
    pub fn new(erst_base_addr: u64, segment_base: u64, segment_size: u32) -> Result<Self, EventRingError> {
        if segment_size < 16 || segment_size > 4096 {
            return Err(EventRingError::SegmentSize);
        }
        let mut erst = EventRingSegmentTable {
            base: erst_base_addr as *mut Trb,
            size: 0
        };
        unsafe {
            erst.add_entry(segment_base, segment_size);
        }

        Ok(ConsumerRingBuffer {
            dequeue: segment_base as *mut Trb,
            ccs: 1,
            erst,
            erst_count: 0,
            ers_size: segment_size,
        })
    }

    pub fn add_segment(&mut self, segment_base: u64, segment_size: u32) -> Result<(), EventRingError> {
        if segment_size < 16 || segment_size > 4096 {
            return Err(EventRingError::SegmentSize);
        }
        unsafe {
            self.erst.add_entry(segment_base, segment_size);
        }
        Ok(())
    }

    // dequeues a block or returns an ring empty error
    pub unsafe fn dequeue(&mut self) -> Result<Trb, EventRingError> {
        // first get the block and see if we own it
        let block: Trb;
        unsafe {
            block = *self.dequeue;
        }

        // if the block's cycle bit does not match then we are at the enqueue pointer meaning that buffer is empty
        if self.ccs as u32 != block.get_cycle() {
            return Err(EventRingError::RingEmptyError);
        }
        
        // move the dequeue pointer
        self.move_dequeue();
        
        Ok(block)
    }

    // moves the dequeue ptr to the next trb
    unsafe fn move_dequeue(&mut self) {
        if self.ers_size == 1 {
            // need to go to a new segment, first check to see if we need to loop back to the beginning
            self.erst_count += 1;
            if self.erst_count == self.erst.get_size() {
                // toggle ccs and set count to 0
                self.ccs ^= 1;
                self.erst_count = 0;
            }
            
            // get the block at index count and then set dequeue to the params and size to the size field
            let entry = self.erst.get_entry(self.erst_count);
            self.dequeue = entry.parameters as *mut Trb;
            self.ers_size = entry.status & 0xFFFF;
        } else {
            // there are still blocks in this segment so just move things
            self.ers_size -= 1;
            self.dequeue = self.dequeue.offset(1);
        }
    }
}
