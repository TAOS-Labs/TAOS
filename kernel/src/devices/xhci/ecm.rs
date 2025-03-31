use crate::{
    constants::memory::PAGE_SIZE,
    debug_println,
    devices::{
        mmio::{self, map_page_as_uncacheable, zero_out_page},
        xhci::{context::SlotContext, XHCIError},
    },
    memory::{frame_allocator::alloc_frame, MAPPER},
};

use super::{
    context::{EndpointContext, InputControlContext},
    ring_buffer::{ProducerRingBuffer, RingType, TransferRequestBlock, TrbTypes},
    wait_for_events_including_command_completion, USBDeviceConfigurationDescriptor,
    USBDeviceDescriptor, USBDeviceEndpointDescriptor, USBDeviceInfo, USBDeviceInterfaceDescriptor,
    XHCI,
};
use alloc::vec::Vec;
use x86_64::structures::paging::Page;

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

#[derive(Debug, Clone, Copy)]
enum ECMDeviceDescriptors {
    DeviceDescriptor(USBDeviceDescriptor),
    ConfigurationDescriptor(USBDeviceConfigurationDescriptor),
    InterfaceDescriptor(USBDeviceInterfaceDescriptor),
    EndpointDescriptor(USBDeviceEndpointDescriptor),
    FunctionalDescriptor(DeviceFunctionalDescriptor),
    EthernetDescriptor(EthernetNetworkingFunctionalDescriptor),
}

pub struct ECMDevice {
    standard_device: USBDeviceInfo,
    descriptors: ECMDeviceDescriptors,
}

const CLASS_CODE_CDC: u8 = 2;
const SUBCLASS_CODE_ECM: u8 = 6;

pub fn find_cdc_device(devices: &mut Vec<USBDeviceInfo>) -> Option<(u8, u8)> {
    for device in devices {
        debug_println!("Device DESC = {:?}", device.descriptor);
        if device.descriptor.b_device_class == CLASS_CODE_CDC {
            for configuration in 0..device.descriptor.b_num_configurations {
                let class_desc =
                    get_class_descriptors_for_configuration(device, configuration).unwrap();
                debug_println!("class_desc = {class_desc:?}");
                for descriptor in class_desc {
                    match descriptor {
                        ECMDeviceDescriptors::InterfaceDescriptor(config) => {
                            if config.b_interface_class == CLASS_CODE_CDC
                                && config.b_interface_sub_class == SUBCLASS_CODE_ECM
                            {
                                return Option::Some((device.slot, configuration));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Option::None
}

pub fn init_cdc_device(mut device: USBDeviceInfo) -> Result<ECMDevice, XHCIError> {
    let bm_request_type: u8 = 0b00000000;
    let b_request: u8 = 9; // Set configuration
                           // let descriptor_type: u8 = 2; // Configuration
                           // let descriptor_idx: u8 = configuration; // Get the second one (FIXME: Hardcoded qemu)
    let w_value: u16 = 1;
    let w_idx: u16 = 0;
    let w_length: u16 = 0;
    let paramaters: u64 = ((w_length as u64) << 48)
        | ((w_idx as u64) << 32)
        | ((w_value as u64) << 16)
        | ((b_request as u64) << 8)
        | (bm_request_type as u64);
    device.send_command_no_data(paramaters)?;

    let config = get_class_descriptors_for_configuration(&mut device, 1).unwrap();
    debug_println!("class_desc = {config:?}");

    // Send configure endpoint
    // We use endpoint 2, both in and out
    debug_println!("device_slot = {}", device.slot);
    let context_ptr: *mut InputControlContext = device.input_context_vaddr.as_mut_ptr();
    let mut context = unsafe { core::ptr::read_volatile(context_ptr) };

    context.set_add_flag(0, 1);
    context.set_add_flag(1, 0);
    // context.set_drop_flag(0, 0);
    // context.set_drop_flag(1, 0);
    context.set_add_flag(2, 1);
    context.set_add_flag(3, 1);

    let slot_context_addr = device.input_context_vaddr + 0x20;
    debug_println!("slot conext addr = {slot_context_addr:?}");
    let slot_context_ptr: *mut SlotContext = slot_context_addr.as_mut_ptr();
    let mut slot_context = unsafe { core::ptr::read_volatile(slot_context_ptr) };
    debug_println!("Slot context = {:?}", slot_context);
    slot_context.offset_3 = 0x10000001;
    unsafe {
        core::ptr::write_volatile(slot_context_ptr, slot_context);
    }
    let ep_1_context_out_addr = device.input_context_vaddr + 0x60;
    let ep1_ctxt_out_ptr: *mut EndpointContext = ep_1_context_out_addr.as_mut_ptr();
    let mut ep1_ctxt_out = unsafe { core::ptr::read_volatile(ep1_ctxt_out_ptr) };
    ep1_ctxt_out.set_cerr(3);
    ep1_ctxt_out.set_eptype(2);
    ep1_ctxt_out.set_max_packet_size(64);
    ep1_ctxt_out.set_dcs(1);
    // Now setup context in
    let ep_1_context_in_addr = device.input_context_vaddr + 0x80;
    let ep1_ctxt_in_ptr: *mut EndpointContext = ep_1_context_in_addr.as_mut_ptr();
    let mut ep1_ctxt_in = unsafe { core::ptr::read_volatile(ep1_ctxt_in_ptr) };
    ep1_ctxt_in.set_cerr(3);
    ep1_ctxt_in.set_eptype(6);
    ep1_ctxt_in.set_max_packet_size(64);
    ep1_ctxt_in.set_dcs(1);
    ep1_ctxt_in.set_average_trb_len(1_600);
    // Set up TRB

    let input_trb_buffer = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let mut mapper = MAPPER.lock();
    let input_trb_address = map_page_as_uncacheable(input_trb_buffer.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    zero_out_page(Page::containing_address(input_trb_address));
    let in_trb = ProducerRingBuffer::new(
        input_trb_address.as_u64(),
        1,
        RingType::Transfer,
        (PAGE_SIZE).try_into().unwrap(),
    )
    .expect("Everything should be alligned");
    ep1_ctxt_in.set_trdequeue_ptr(input_trb_buffer.start_address().as_u64());

    let output_trb_buffer = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let output_trb_address =
        map_page_as_uncacheable(output_trb_buffer.start_address(), &mut mapper)
            .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    zero_out_page(Page::containing_address(output_trb_address));
    let out_trb = ProducerRingBuffer::new(
        output_trb_address.as_u64(),
        1,
        RingType::Transfer,
        (PAGE_SIZE).try_into().unwrap(),
    )
    .expect("Everything should be alligned");
    ep1_ctxt_out.set_trdequeue_ptr(output_trb_buffer.start_address().as_u64());

    unsafe {
        core::ptr::write_volatile(context_ptr, context);
    }
    unsafe {
        core::ptr::write_volatile(ep1_ctxt_in_ptr, ep1_ctxt_in);
    }
    unsafe {
        core::ptr::write_volatile(ep1_ctxt_out_ptr, ep1_ctxt_out);
    }

    unsafe {
        core::ptr::write_volatile(context_ptr, context);
    }

    let big_device: u32 = device.slot.into();
    let block = TransferRequestBlock {
        parameters: (device.input_context_vaddr - mapper.phys_offset()),
        status: 0,
        control: ((big_device << 24) | ((TrbTypes::ConfigEpCmd as u32) << 10)),
    };
    let mut info = XHCI.lock().clone().unwrap();
    let command_ring_lock = info.command_ring.clone();
    let mut command_ring = command_ring_lock.lock();
    unsafe {
        command_ring
            .enqueue(block)
            .map_err(|_| XHCIError::CommandRingError)?
    };
    drop(command_ring);
    let doorbell_base: *mut u32 =
        (info.base_address + info.capablities.doorbell_offset as u64) as *mut u32;
    unsafe { core::ptr::write_volatile(doorbell_base, 0) };
    wait_for_events_including_command_completion(&mut info, &mapper)?;

    // Now get out ethernet address
    let mut str_addr: u8 = 0;
    for descriptor in config {
        match descriptor {
            ECMDeviceDescriptors::EthernetDescriptor(desc) => {
                str_addr = desc.imac_address;
            }
            _ => {}
        }
    }
    drop(mapper);
    get_eth_addr(&mut device, str_addr);

    let config = get_class_descriptors_for_configuration(&mut device, 1).unwrap();
    debug_println!("class_desc = {config:?}");

    Result::Err(XHCIError::UnknownPort)
}

fn get_eth_addr(device: &mut USBDeviceInfo, idx: u8) -> Result<(), XHCIError> {
    let data_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    debug_println!("Data phys_addr = {:X}", data_frame.start_address().as_u64());
    debug_println!("idx = {idx}");
    let mut mapper = MAPPER.lock();
    let data_addr = mmio::map_page_as_uncacheable(data_frame.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    drop(mapper);
    let bm_request_type: u8 = 0b10000000;
    let b_request: u8 = 6; // Get descriptor
    let descriptor_type: u8 = 3; //
    let descriptor_idx: u8 = idx;
    let w_value: u16 = ((descriptor_type as u16) << 8) | (descriptor_idx as u16);
    let w_idx: u16 = 0x09; // English language id
    let w_length: u16 = 1024;
    let paramaters: u64 = ((w_length as u64) << 48)
        | ((w_idx as u64) << 32)
        | ((w_value as u64) << 16)
        | ((b_request as u64) << 8)
        | (bm_request_type as u64);

    device
        .send_command(paramaters, data_frame.start_address(), 1024)
        .unwrap();
    let mut eth_vec: Vec<u8> = Vec::new();
    for str_idx in 0..32 {
        let data_pointer: *const u8 = (data_addr + str_idx).as_ptr();
        let value = unsafe { core::ptr::read_volatile(data_pointer) };
        if value >= 48 {
            eth_vec.push(value - 48);
        }
    }
    // let eth_addr: &[u8]= unsafe {core::slice::from_raw_parts(data_pointer, 12)};
    debug_println!("Eth addr = {eth_vec:?}");
    Result::Ok(())
}

fn get_class_descriptors_for_configuration(
    device: &mut USBDeviceInfo,
    configuration: u8,
) -> Result<Vec<ECMDeviceDescriptors>, XHCIError> {
    let data_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    debug_println!("Data phys_addr = {:X}", data_frame.start_address().as_u64());
    let mut mapper = MAPPER.lock();
    let data_addr = mmio::map_page_as_uncacheable(data_frame.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    drop(mapper);
    let bm_request_type: u8 = 0b10000000;
    let b_request: u8 = 6; // Get descriptor
    let descriptor_type: u8 = 2; // Configuration
    let descriptor_idx: u8 = configuration; // Get the second one (FIXME: Hardcoded qemu)
    let w_value: u16 = ((descriptor_type as u16) << 8) | (descriptor_idx as u16);
    let w_idx: u16 = 0;
    let w_length: u16 = 1024;
    let paramaters: u64 = ((w_length as u64) << 48)
        | ((w_idx as u64) << 32)
        | ((w_value as u64) << 16)
        | ((b_request as u64) << 8)
        | (bm_request_type as u64);

    device
        .send_command(paramaters, data_frame.start_address(), 1024)
        .unwrap();

    let mut descriptors = Vec::new();
    let data_to_do: *const USBDeviceConfigurationDescriptor = data_addr.as_ptr();
    let config_descriptor = unsafe { core::ptr::read_volatile(data_to_do) };
    descriptors.push(ECMDeviceDescriptors::ConfigurationDescriptor(
        config_descriptor,
    ));
    let total_size: usize = config_descriptor.w_total_length.into();
    let mut bytes_read: usize = config_descriptor.b_length.try_into().unwrap();

    while bytes_read < total_size {
        let desc_vaddr = data_addr + bytes_read.try_into().unwrap();
        let desc_ptr: *const DeviceFunctionalDescriptor = desc_vaddr.as_ptr();
        let base_device = unsafe { core::ptr::read_unaligned(desc_ptr) };
        match base_device.b_descriptor_type {
            4 => {
                // Interface
                let interface_ptr: *const USBDeviceInterfaceDescriptor = desc_vaddr.as_ptr();
                let interface_descriptor = unsafe { core::ptr::read_unaligned(interface_ptr) };
                descriptors.push(ECMDeviceDescriptors::InterfaceDescriptor(
                    interface_descriptor,
                ));
            }
            5 => {
                // Endpoint
                let endpoint_ptr: *const USBDeviceEndpointDescriptor = desc_vaddr.as_ptr();
                let endpoint_descriptor = unsafe { core::ptr::read_unaligned(endpoint_ptr) };
                descriptors.push(ECMDeviceDescriptors::EndpointDescriptor(
                    endpoint_descriptor,
                ));
            }
            0x24 | 0x25 => {
                // CS Interface / CS Endpoint
                if base_device.b_descriptor_subtype == 0xF {
                    let networking_ptr: *const EthernetNetworkingFunctionalDescriptor =
                        desc_vaddr.as_ptr();
                    let networking_desc = unsafe { core::ptr::read_unaligned(networking_ptr) };
                    descriptors.push(ECMDeviceDescriptors::EthernetDescriptor(networking_desc));
                }
            }
            _ => {
                panic!("Unreckonised descriptor type")
            }
        }
        bytes_read += base_device.b_length as usize;
    }
    Result::Ok(descriptors)
}
