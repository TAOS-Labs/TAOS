enum TrbTypes {
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
    MfindexWrapEvent = 39
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
    NoOp
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
    SetExtendedPropCmd
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
    MfindexWrapEvent
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
/// A generic struct for Transfer Request Blocks (TRBs).
/// Precise setting and getting of specific fields for a given TRB shall be done
/// by the xHCI driver. See section 6.4 of the xHCI specs for more details.
struct TransferRequestBlock {
    parameters: u64,
    status: u32,
    control: u32,
}

type Trb = TransferRequestBlock;

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
    Transfer
}

pub enum RingBufferError {
    EnqueueError,
    DequeueError
}

#[derive(Debug, Clone)]
/// Implements a ring buffer for use with the different rings associated with
/// the xHCI.
struct RingBuffer {
    enqueue: *mut Trb,
    dequeue: *mut Trb,
    cycle_state: u8,
    ring: RingType
}

impl RingBuffer {
    pub fn new(base_addr: u64, cycle_state: u8, ring_type: RingType, size: isize) -> Self {
        // ensure that the base address is aligned to 16
        assert!(base_addr % 16 == 0);
        // make sure that size is a multiple of 16
        assert!(size % 16 == 0);

        // initialize the link block at the end of this segment
        let num_blocks = size / 16;
        let enqueue = base_addr as *mut Trb;
        unsafe {
            let mut last = *enqueue.offset(num_blocks - 1);
            // sets the trb type to Link and the toggle cycle bit to 1
            last.control =  0x1802;
            last.parameters = base_addr;
        }
        RingBuffer {
            enqueue: base_addr as *mut Trb,
            dequeue: base_addr as *mut Trb,
            cycle_state,
            ring: ring_type
        }
    }

    pub fn set_enqueue(&mut self, addr: u64) {
        assert!(addr % 16 == 0);
        self.enqueue = addr as *mut Trb;
    }

    pub fn set_dequeue(&mut self, addr: u64) {
        assert!(addr % 16 == 0);
        self.dequeue = addr as *mut Trb;
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

    pub unsafe fn is_ring_full(&self) -> bool {
        let next_enq: *mut Trb;
        // check if adding 1 to enqueue would make it point to a link trb
        if self.is_next_link() {
            // if so, set next_enq to the pointer stored in trb.parameters
            let next_trb = *self.enqueue;
            next_enq = (next_trb.parameters & 0xF) as *mut Trb;
        } else {
            // otherwise, just set next_enq to enqueue offsetted by one
            next_enq = self.enqueue.offset(1);
        }
        self.dequeue == next_enq
    }

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
            self.enqueue = (trb.parameters & 0xF) as *mut Trb;
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
            self.dequeue = (trb.parameters & 0xF) as *mut Trb;
        }
    }

    pub unsafe fn enqueue(&mut self, block: Trb) -> Result<(), RingBufferError> {
        // If the ring is full then return enqueue error
        if self.is_ring_full() {
            return Err(RingBufferError::EnqueueError);
        }
        // copy the contents of block into enqueue
        // TODO: make sure this copies like I want it to
        *self.enqueue = block;

        // increment the enqueue pointer
        self.increment_enqueue();
        Result::Ok(())
    }

    pub unsafe fn dequeue(&mut self) -> Result<Trb, RingBufferError> {
        // If the ring is empty then reurn dequeue error
        if self.is_ring_empty() {
            return Err(RingBufferError::DequeueError);
        }

        // get the block
        let block = *self.dequeue;

        // increment the dequeue pointer
        self.increment_dequeue();

        Result::Ok(block)
    }
}