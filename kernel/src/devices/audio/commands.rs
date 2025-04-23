use crate::debug_println;

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
/// Intel HDA Verb Commands
pub enum HdaVerb {
    GetParameter = 0xF00,
    GetConnectionListEntry = 0xF02,
    GetPowerState = 0xF05,
    SetPowerState = 0x705,
    GetPinControl = 0xF07,
    GetEAPDBTLEnable = 0xF0C,
    SetEAPDBTLEnable = 0x70C,
    SetPinControl = 0x707,
    GetConfigDefault = 0xF1C,
    GetVolumeKnobCaps = 0x13,
    SetConverterFormat = 0x02,
    SetAmplifierGain = 0x03,
    SetStreamChannel = 0x706,
    SetDacEnable = 0x701,
    KickStart = 0xF81,
    GetBeepGen = 0xF0A,
    SetBeepGen = 0x70A,
}

impl HdaVerb {
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
/// Codec Node Parameters that can be used with GetParameter verb. These values were taken from the OSDev page for the Intel-HDA.
pub enum NodeParams {
    VendorDeviceID = 0x0,
    RevisionID = 0x2,
    NodeCount = 0x4,
    FunctionGroupType = 0x5,
    AudioGroupCap = 0x8,
    AudioWidgetCap,
    SupportPCMRates,
    SupportedFormats,
    PinCap,
    InputAmplifierCap,
    ConnectionListLength,
    SupportedPowerStates,
    ProcessingCap,
    GPIOCount,
    OutputAmplifierCap,
    VolumeCap,
}

impl NodeParams {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Copy, Clone, Debug)]
/// A struct representing an entry in the CORB
pub struct CorbEntry {
    /// The data of the command, the description of each bit range is defined as follows:
    /// - `[31:28]`: Codec Address
    /// - `[27:20]`: Node Index
    /// - `[19:8]`: Command
    /// - `[7:0]`: Data
    pub cmd: u32
}

impl CorbEntry {
    /// creates a new corb entry
    /// 
    /// # Arguments
    /// * `codec`: the address of the target codec
    /// * `nid`: the id of the target node
    /// * `command`: the command to be sent
    /// * `data`: the data to be sent with the command
    /// 
    /// # Returns
    /// `self` initialized with the values passed in
    pub fn create_entry(codec: u32, nid: u32, command: HdaVerb, data: u16) -> Self {
        debug_println!("creating a command with codec address: 0x{:X}, nid: 0x{:X}, command: {:?}, data: 0x{:X}", codec, nid, command, data);
        let command_num = command.as_u32();
        let cmd_lo: u32;
        if command_num == HdaVerb::SetAmplifierGain.as_u32() || command_num == HdaVerb::SetConverterFormat.as_u32() {
            // debug_println!("cmd4");
            cmd_lo = (command_num << 16) | (data as u32 & 0xFFFF);
        } else {
            // debug_println!("cmd12");
            cmd_lo = (command_num << 8) | ((data & 0xFF) as u32);
        }
        let cmd = (codec << 28) | (nid << 20) | cmd_lo;
        debug_println!("setting the cmd field as: 0x{:X}", cmd);
        Self {
            cmd
        }
    }
    
    /// returns cmd for debugging
    pub fn get_cmd(&self) -> u32 {
        self.cmd
    }
}

// TODO: add #[repr(C)] ?
#[derive(Copy, Clone, Debug)]
/// A struct representing an entry in the RIRB
pub struct RirbEntry {
    /// The response data received from the codec
    response: u32,
    /// Infor added to the response by the controller
    resp_ex: u32,
}

impl RirbEntry {
    /// gets the codec's response
    /// 
    /// # Returns
    /// `response`
    pub fn get_response(&self) -> u32 {
        self.response
    }

    pub fn get_response_ex(&self) -> u32 {
        self.resp_ex
    }

    /// gets the codec address from this entry
    /// 
    /// # Returns
    /// bits `[3:0]` of `resp_ex`
    pub fn get_codec_address(&self) -> u8 {
        (self.resp_ex & 0xF) as u8
    }

    /// checks if this response is unsolicited
    /// 
    /// # Returns
    /// * `true` if bit `4` of `resp_ex` is set, indicating that this was an unsolicited response.
    /// * `false` otherwise, indicating that this was a solicited response.
    pub fn is_unsolicited_resp(&self) -> bool {
        self.resp_ex & 0x10 != 0
    }

    pub fn print_response(&self) {
        debug_println!("Response: 0x{:X}, resp_ex: {:X}", self.response, self.resp_ex);
    }
}