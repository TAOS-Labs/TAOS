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
    Disallowed,
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
#[derive(Debug, Clone)]
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
