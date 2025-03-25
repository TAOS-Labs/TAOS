use super::{
    USBDeviceConfigurationDescriptor, USBDeviceDescriptor, USBDeviceEndpointDescriptor,
    USBDeviceInfo, USBDeviceInterfaceDescriptor,
};
use alloc::vec::Vec;

#[repr(u8)]
enum USBDescriptorTypes {
    Device = 0x1,
    Configuration = 0x2,
    String = 0x3,
    Endpoint = 0x4,
    DeviceQualifier = 0x6,
    OtherSpeedConfiguration = 0x7,
    InterfacePower = 0x8,
    CsInterface = 0x24,
    CsEndpoint = 0x25,
}

#[repr(u8)]
enum CDCSubTypes {
    Header = 0x00,
    Union = 0x06,
    CountrySelection = 0x07,
    EthernetNetwoking = 0x0F,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct DeviceFunctionalDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_descriptor_subtype: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct HeaderFunctionalDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_descriptor_subtype: u8,
    bcd_cdc: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
// Note that the subordinate descriptors also exist, but are not included
// in this struct
struct UnionFunctionalDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_descriptor_subtype: u8,
    b_control_interface: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct EthernetNetworkingFunctionalDescriptor {
    b_function_length: u8,
    b_descriptor_type: u8,
    b_descriptor_subtype: u8,
    imac_address: u8,
    bm_ethernet_statistics: u32,
    w_max_segment_size: u16,
    w_number_mc_filters: u16,
    b_number_power_filters: u8,
}

enum ECMDeviceDescriptors {
    DeviceDescriptor(USBDeviceDescriptor),
    ConfigurationDescriptor(USBDeviceConfigurationDescriptor),
    InterfaceDescriptor(USBDeviceInterfaceDescriptor),
    EndpointDescriptor(USBDeviceEndpointDescriptor),
    FunctionalDescriptor(DeviceFunctionalDescriptor),
}

const CLASS_CODE_CDC: u8 = 2;
const SUBCLASS_CODE_ECM: u8 = 6;

pub fn find_cdc_device(devices: Vec<USBDeviceInfo>) -> Option<USBDeviceInfo> {
    for device in devices {
        if device.descriptor.b_device_class == 2 {}
    }

    Option::None
}

fn get_class_descriptors_for_configuration(
    device: USBDeviceInfo,
    configuration: u8,
) -> Vec<ECMDeviceDescriptors> {
    Vec::new()
}
