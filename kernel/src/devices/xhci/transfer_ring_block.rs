/// The list of TRB types that are allowed on the transfer ring
pub enum transfer_ring_types {
    RESERVED,
    NORMAL,
    SETUP_STAGE,
    DATA_STAGE,
    STATUS_STAGE,
    ISOCH,
    LINK,
    EVENT_DATA,
    NO_OP,
    DISALLOWED
}

/// The list of types that are allowed on the command ring
pub enum command_ring_types {
    LINK = 6,
    ENABLE_SLOT_CMD = 9,
    DISABLE_SLOT_CMD,
    ADDRESS_DEVICE_CMD,
    CONFIG_EP_CMD,
    EVAL_CONTEXT_CMD,
    REST_EP_CMD,
    STOP_EP_CMD,
    SET_TR_DEQPTR_CMD,
    RESET_DEVICE_CMD,
    FORCE_EVENT_CMD,
    NEGOTIATE_BANDWITH_CMD,
    SET_LATENCY_TOLERANCE_CMD,
    GET_PORT_BANDWITH_CMD,
    FORCE_HEADER_CMD,
    NO_OP_CMD,
    GET_EXTENDED_PROP_CMD,
    SET_EXTENDED_PROP_CMD,
}

/// The list of types that are allowed on the event ring
pub enum event_ring_types {
    TRANSFER_EVENT = 32,
    CMD_COMPLETE_EVENT,
    PORT_STAT_CHANGE_EVENT,
    BANDWITH_REQ_EVENT,
    DOORBELL_EVENT,
    HC_EVENT,
    DEVICE_NOTIF_EVENT,
    MFINDEX_WRAP_EVENT
}

#[repr(C, packed)]
#[derive(Debug, Clone)]
/// A generic struct for Transfer Request Blocks (TRBs).
/// Precise setting and getting of specific fields for a given TRB shall be done
/// by the xHCI driver. See section 6.4 of the xHCI specs for more details.
struct transfer_request_block {
    parameters: u64,
    status: u32,
    control: u32
}

type trb = transfer_request_block;

impl transfer_request_block {
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

