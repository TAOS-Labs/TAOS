/// Intel HDA Verb Commands
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum HdaVerb {
    GetParameter = 0xF00,
    GetConnectionListEntry = 0xF02,
    GetPowerState = 0xF05,
    SetPowerState = 0x705,
    GetPinControl = 0xF07,
    SetPinControl = 0x707,
    GetConfigDefault = 0x1C,
    GetAmpCapabilities = 0x0D,
    GetAmpOutCaps = 0x12,
    GetVolumeKnobCaps = 0x13,
    GetPinCaps = 0x0C,
    GetConnListLen = 0x0E,
    SetConverterFormat = 0x02,
    SetAmplifierGain = 0x03,
    SetStreamChannel = 0x706,
    SetDacEnable = 0x701,
    KickStart = 0xF81,
} 
