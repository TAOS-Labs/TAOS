#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
/// See section 6.2.2 of xHCI specs
/// This structure should only be 32 bytes if Context Size field in the
/// HCCPARAMS1 register is '0', otherwise it is 64 bytes with bytes 32
/// to 64 reserved for the xHCI
pub struct SlotContext {
    offset_0: u32,
    offset_1: u32,
    offset_2: u32,
    offset_3: u32,
    offset_4: u32,
    offset_5: u32,
    offset_6: u32,
    offset_7: u32,
}

impl SlotContext {
    /// Retrieves the route string from the slot contex.
    /// The route string is only 20 bits wide and is used
    /// by hubs to route packets.
    pub fn get_route_string(&self) -> u32 {
        self.offset_0 & 0xFFFFF
    }

    /// Retrieves the route string from the slot contex.
    /// The route string is only 20 bits wide and is used
    /// by hubs to route packets.
    pub fn set_route_string(&mut self, value: u32) {
        assert!((0..=0xFFFFF).contains(&value));
        self.offset_0 = (self.offset_0 & !0xFFFFF) | value;
    }

    /// Retrieves the speed from the slot context.
    /// This field is 4 bits wide indicates the speed of the device.
    /// This field is deprecated and should be reserved.
    pub fn get_speed(&self) -> u32 {
        (self.offset_0 >> 20) & 0xF
    }

    /// Retrieves the multi-tt bit from the slot context.
    /// This bit is 1 if multiple transaction translators (TTs) are needed.
    pub fn get_mtt(&self) -> u32 {
        (self.offset_0 >> 25) & 1
    }

    /// Sets the MTT field to value.
    /// value is expected to be one bit.
    pub fn set_mtt(&mut self, value: u32) {
        assert!(value == 0 || value == 1);
        self.offset_0 = (self.offset_0 & !0x2000000) | (value << 25);
    }

    /// Retrieves the hub bit from the slot context.
    /// This bit is 1 if this device is a USB hub, 0 for a USB function.
    pub fn get_hub(&self) -> u32 {
        (self.offset_0 >> 26) & 1
    }

    /// Sets the hub field to value.
    /// value is expected to be one bit.
    pub fn set_hub(&mut self, value: u32) {
        assert!(value == 0 || value == 1);
        self.offset_0 = (self.offset_0 & !0x4000000) | (value << 26);
    }

    /// Retrieves the context entries from the slot context.
    /// This field is only 5 bits wide and it identifies the index of the last
    /// valid endpoint context within the parent device context structure.
    pub fn get_context_entries(&self) -> u32 {
        (self.offset_0 >> 27) & 0x1F
    }

    /// Sets the context entries field to value.
    /// value is expected to be 5 bits.
    /// This method should only be used if this is an input context entries.
    pub fn set_context_entries(&mut self, value: u32) {
        assert!((0..=0b11111).contains(&value));
        self.offset_0 = (self.offset_0 & 0x7FFFFFF) | (value << 27);
    }

    /// Retrieves the max exit latency from the slot context.
    /// This field is 16 bits wide. The value returned is the worst case time
    /// to wake up all the links in the path to the device in microseconds.
    pub fn get_max_exit_latency(&self) -> u32 {
        self.offset_1 & 0xFFFF
    }

    /// Retrieves the root hub port number from the slot context.
    /// This field is only 8 bits wide and identifies the root hub port number
    /// used to access the device.
    pub fn get_root_hub_port(&self) -> u32 {
        (self.offset_1 >> 16) & 0xff
    }

    /// Retrieves the root hub port number from the slot context.
    /// This field is only 8 bits wide and identifies the root hub port number
    /// used to access the device.
    pub fn set_root_hub_port(&mut self, value: u32) {
        assert!((0..=0xFF).contains(&value));
        self.offset_1 = (self.offset_1 & (!(0xFF << 16))) | (value << 16);
    }

    /// Retrieves the number of ports from the slot context.
    /// This field is only 8 bits wide. If this devices is a hub, the value returned
    /// is the number of downstream ports supported on this device
    pub fn get_num_ports(&self) -> u32 {
        (self.offset_1 >> 24) & 0xFF
    }

    /// Sets the number of ports field to value.
    /// value is expected to be 8 bits.
    pub fn set_num_ports(&mut self, value: u32) {
        assert!((0..=0xFF).contains(&value));
        self.offset_1 = (self.offset_1 & 0xFFFFFF) | (value << 24);
    }

    /// Retrieves the parent hub slot id from the slot context.
    /// This field is only 8 bits wide and contains the slot id of the parent hub.
    pub fn get_parent_hub_slot(&self) -> u32 {
        self.offset_2 & 0xFF
    }

    /// Retrieves the parent port number from the slot context.
    /// This field is only 8 bits wide and contains the port number of the parent hub.
    pub fn get_parent_port(&self) -> u32 {
        (self.offset_2 >> 8) & 0xFF
    }

    /// Retrieves the TT think time from the slot context.
    /// This field is only 2 bits wide and contains the time that the TT of the hub
    /// requires to proceed to the next transaction.
    pub fn get_think_time(&self) -> u32 {
        (self.offset_2 >> 16) & 0x3
    }

    /// Retrieves the interrupter target from the slot context.
    /// This field is only 10 bits wide and defines the index of the interrupter that
    /// receives the events generated by this slot.
    pub fn get_interrupter_target(&self) -> u32 {
        (self.offset_2 >> 22) & 0x3FF
    }

    /// Retrieves the USB device address from the slot context.
    /// This field is only 8 bits wide and contains the address assigned to the USB device
    /// by the xHC.
    pub fn get_device_address(&self) -> u32 {
        self.offset_3 & 0xFF
    }

    /// Retrieves the slot state from the slot context.
    /// This field is only 5 bits wide. This field is updated by the xHC with the
    /// device slot transitions from one state to another.
    pub fn get_slot_state(&self) -> u32 {
        (self.offset_3 >> 27) & 0x1F
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(dead_code)]
/// See section 6.2.3 of the xHCI specs.
/// This structure should only be 32 bytes if Context Size field in the
/// HCCPARAMS1 register is '0', otherwise it is 64 bytes with bytes 32
/// to 64 reserved for the xHCI
pub struct EndpointContext {
    pub offset_0: u32,
    pub offset_1: u32,
    offset_2: u32,
    offset_3: u32,
    offset_4: u32,
    offset_5: u32,
    offset_6: u32,
    offset_7: u32,
}

impl EndpointContext {
    /// retrieves the Endpoint State from the endpoint context
    /// This field is only 3 bits wide and identifies the current
    /// operational state of the endpoint.
    pub fn get_ep_state(&self) -> u32 {
        self.offset_0 & 0x7
    }

    /// sets the Endpoint State field of the endpoint context to value.
    /// value is expected to be 3 bits wide.
    pub fn set_ep_state(&mut self, value: u32) {
        self.offset_0 = (self.offset_0 & !0x7) | value;
    }

    /// retrieves the mult field from the endpoint context.
    /// this field is only 2 bits wide and identifies the maximum number of bursts
    /// within an interval that this endpoint supports
    pub fn get_mult(&self) -> u32 {
        (self.offset_0 >> 8) & 0x3
    }

    /// retrieves the mult field from the endpoint context.
    /// this field is only 2 bits wide and identifies the maximum number of bursts
    /// within an interval that this endpoint supports
    pub fn set_mult(&mut self, value: u32) {
        assert!(value <= 0x3);
        self.offset_0 &= !(0x3 << 8);
        self.offset_0 |= value << 8;
    }

    /// retrieves the Max Primary Streams field from the endpoint context.
    /// This field is only 5 bits wide and identifies the max number of primary
    /// stream ids this endpoint supports.
    pub fn get_maxpstreams(&self) -> u32 {
        (self.offset_0 >> 10) & 0x1F
    }

    /// retrieves the Max Primary Streams field from the endpoint context.
    /// This field is only 5 bits wide and identifies the max number of primary
    /// stream ids this endpoint supports.
    pub fn set_maxpstreams(&mut self, value: u8) {
        assert!(value <= 0x1F);
        let value_32: u32 = value.into();
        self.offset_0 &= !(0x1F << 10);
        self.offset_0 |= value_32 << 10;
    }

    /// retrieves the Linear Stream Array field from the endpoint context.
    /// This field is only 1 bit and identifies how a stream id shall be interpreted
    pub fn get_lsa(&self) -> u32 {
        (self.offset_0 >> 15) & 0x1
    }

    /// retrieves the Interval field from the endpoint context.
    /// This field is only 8 bits wide. The value returned is the period between
    /// consecutive requests to a USB endpoint in 125 microsecond increments
    pub fn get_interval(&self) -> u32 {
        (self.offset_0 >> 16) & 0xFF
    }

    /// Sets the interval (The period between consequtive enrequests to a USB
    /// endpoint to send or recieve data). This is expressed in 125 us intrements
    pub fn set_interval(&mut self, value: u8) {
        let value_32: u32 = value.into();
        self.offset_0 = self.offset_0 & !((0xFF) << 16) | (value_32 << 16);
    }

    /// Retrieves the Error Count from the endpoint context.
    /// This field is only 2 bits wide and identifies the number of consecutive
    /// errors allowed whiled making a TD.
    pub fn get_cerr(&self) -> u32 {
        (self.offset_1 >> 1) & 0x3
    }

    /// Sets the Error Count field of the endpoint context to value.
    /// value is expected to only be 2 bits wide.
    pub fn set_cerr(&mut self, value: u32) {
        self.offset_1 = (self.offset_1 & !0x6) | (value << 1);
    }

    /// Retrieves the Endpoint Type field of the endpoint context.
    /// This field is 3 bits wide and indicates if an endpoint context is valid
    /// and the type of endpoint it defines. Zero indicates an invalid context.
    pub fn get_eptype(&self) -> u32 {
        (self.offset_1 >> 3) & 0x7
    }

    /// Sets the Endpoint Type field of the endpoint context to value.
    /// value is expected to be 3 bits wide.
    pub fn set_eptype(&mut self, value: u32) {
        self.offset_1 = (self.offset_1 & !0x38) | (value << 3);
    }

    /// Retrieves the Host Initiate Disable field from the endpoint context.
    /// This field is only 1 bit. A value of 1 means the host initiated stream
    /// feature is disabled.
    pub fn get_hid(&self) -> u32 {
        (self.offset_1 >> 7) & 0x1
    }

    /// Sets the Host Initiate Disable field of the endpoint context to value.
    /// value is expected to be 1 bit wide.
    pub fn set_hid(&mut self, value: u32) {
        self.offset_1 = (self.offset_0 & !0x80) | (value << 7);
    }

    /// Retrieves the Max Burst Size field from the endpoint context.
    /// This field is only 8 bits wide and indicates the maximum number of
    /// consecutive USB transactions that should be executed per scheduling opportunity.
    pub fn get_max_burst_size(&self) -> u32 {
        (self.offset_1 >> 8) & 0xFF
    }

    /// Sets the Max Burst Size field of the endpoint context to value.
    /// value is expected to be 8 bits.
    pub fn set_max_burst_size(&mut self, value: u32) {
        self.offset_1 = (self.offset_1 & !0xFF00) | (value << 8);
    }

    /// Retrieves the Max Packet Size field from the endpoint context.
    /// This field is only 16 bits wide and indicates the maximum packet size in
    /// bytes that this endpoint can use
    pub fn get_max_packet_size(&self) -> u32 {
        (self.offset_1 >> 16) & 0xFFFF
    }

    /// Sets the Max Packet Size field of the endpoint context to value.
    /// value is expected to be 16 bits wide.
    pub fn set_max_packet_size(&mut self, value: u32) {
        self.offset_1 = (self.offset_1 & 0x0000FFFF) | (value << 16);
    }

    /// Retrieves the Dequeue Cycle State field of from the endpoint context.
    /// This field is only 1 bit and identifies the value of the xHC Consumer
    /// Cycle State (CCS) flag for the TRB.
    pub fn get_dcs(&self) -> u32 {
        self.offset_2 & 0x1
    }

    /// Sets the Dequeue Cycle State field of the endpoint context to value.
    /// value is expected to be only 1 bit.
    pub fn set_dcs(&mut self, value: u32) {
        self.offset_2 = (self.offset_1 & !0x1) | value;
    }

    /// Retrieves the TR Dequeue Pointer from the endpoint context.
    /// TODO: make sure that this method is needed cause this field might only be used by the xHC
    pub fn get_trdequeue_ptr(&self) -> u64 {
        let deqptrlo: u64 = (self.offset_2 & 0xFFFFFFF0).into();
        let deqptrhi: u64 = (self.offset_3).into();
        (deqptrhi << 32) | deqptrlo
    }

    /// Retrieves the TR Dequeue Pointer from the endpoint context.
    pub fn set_trdequeue_ptr(&mut self, value: u64) {
        assert!(value & 16 == 0);
        let value_lo: u32 = (value & 0xFFFFFFFF)
            .try_into()
            .expect("Masked out high order bits");
        let value_hi: u32 = ((value & (0xFFFFFFFF << 32)) >> 32)
            .try_into()
            .expect("Shifted out high order bits");

        self.offset_2 &= 0xF;
        self.offset_2 |= value_lo;
        self.offset_3 = value_hi;
    }

    /// Retrieves the Averege TRB Length field from the endpoint context.
    /// This field is only 16 bits wide and represents the length of the TRBs
    /// executed by this endpoint.
    pub fn get_average_trb_len(&self) -> u32 {
        self.offset_4 & 0xFFFF
    }

    /// Sets the Average TRB Length field of the endpoint context to value.
    /// value is expected to be 16 bits wide.
    pub fn set_average_trb_len(&mut self, value: u32) {
        self.offset_4 = (self.offset_4 & !0xFFFF) | value;
    }

    /// retrieves the Max Endpoint Service Time Interval Payload field from the endpoint context.
    /// This field is only 24 bits wide. if LEC (whatever that is) is 0 then this
    /// field is invalid
    pub fn get_max_esit_payload(&self) -> u32 {
        let esitlo: u32 = (self.offset_4 >> 16) & 0xFFFF;
        let esithi: u32 = (self.offset_0 >> 24) & 0xFF;
        (esithi << 16) | esitlo
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone)]
#[allow(dead_code)]
/// See section 6.2.4.1 of the xHCI specs.
/// The Context Size field of the HCCPARAMS1 register does not apply to this
/// structure, it is always 16 bytes in size.
struct StreamContext {
    offset_0: u32,
    offset_1: u32,
    offset_2: u32,
    offset_3: u32,
}

#[allow(dead_code)]
impl StreamContext {
    /// Retrieves the Dequeue Cycle State field from the stream context.
    /// This field is only 1 bit wide and identifies the value of the xHC Consumer
    /// Cycle State (CCS) flag for the TRB.
    fn get_dcs(&self) -> u32 {
        self.offset_0 & 0x1
    }

    /// Retrieves the Stream Context Type field from the stream context.
    /// This field is only 3 bits wide and identifies certain values.
    /// See table 6-13 in section 6.2.4.1 of the xHCI specs for more info.
    fn get_sct(&self) -> u32 {
        (self.offset_0 >> 1) & 0x7
    }

    /// Retrieves the TR Dequeue Pointer field from the stream context.
    fn get_tr_deq_ptr(&self) -> u64 {
        let trdeqlo: u64 = (self.offset_0 & !0xF).into();
        let trdeqhi: u64 = (self.offset_1).into();
        (trdeqhi << 32) | trdeqlo
    }

    /// Sets the TR Dequeue Pointer of the stream context to address.
    fn set_tr_deq_ptr(&mut self, address: u64) {
        let trdeqlo: u32 = (address & 0xFFFFFFF0) as u32;
        let trdeqhi: u32 = ((address >> 32) & 0xFFFFFFFF) as u32;
        self.offset_0 = (self.offset_0 & 0xF) | trdeqlo;
        self.offset_1 = trdeqhi;
    }

    /// Retrieves the Stopped EDTLA field from the stream context.
    /// This field is 24 bits wide and identifies the value of the EDTLA when
    /// the stream is in the stopped state.
    fn get_stopped_edtla(&self) -> u32 {
        self.offset_2 & 0xFFFFFF
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
/// See section 6.2.5.1 of the xHCI specs.
/// This structure should only be 32 bytes if Context Size field in the
/// HCCPARAMS1 register is '0', otherwise it is 64 bytes with bytes 32
/// to 64 reserved for the xHCI
pub struct InputControlContext {
    offset_0: u32,
    offset_1: u32,
    offset_2: u32,
    offset_3: u32,
    offset_4: u32,
    offset_5: u32,
    offset_6: u32,
    config_value: u8,
    interface_number: u8,
    alternate_setting: u8,
    rsvdz: u8,
}

impl InputControlContext {
    /// Retrieves the value of the Drop Context flag of the bit at the index
    /// bit position. Index must be > 1 and < 32.
    pub fn get_drop_flag(&self, index: u32) -> u32 {
        assert!((2..32).contains(&index));
        (self.offset_0 >> index) & 1
    }

    /// Sets the Drop Context flag at the index bit position to value.
    /// index must be > 1 and < 32.
    /// value is expected to be 1 bit.
    pub fn set_drop_flag(&mut self, index: u32, value: u32) {
        assert!((2..32).contains(&index));
        assert!(value == 0 || value == 1);
        self.offset_0 = (self.offset_0 & !(1 << index)) | (value << index);
    }

    /// Retrieves the value of the Add Context flag of the bit at the index
    /// bit position. Index must be >= 0 and < 32.
    pub fn get_add_flag(&self, index: u32) -> u32 {
        assert!((0..32).contains(&index));
        (self.offset_1 >> index) & 1
    }

    /// Sets the Add Context flag at the index bit position to value.
    /// index must be >= 0 and < 32.
    /// value is expected to be 1 bit.
    pub fn set_add_flag(&mut self, index: u32, value: u32) {
        assert!((0..32).contains(&index));
        assert!(value == 0 || value == 1);
        self.offset_1 = (self.offset_1 & !(1 << index)) | (value << index);
    }
}
