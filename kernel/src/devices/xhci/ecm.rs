use core::marker::PhantomData;

use crate::{
    constants::memory::PAGE_SIZE,
    devices::{
        mmio::{self, map_page_as_uncacheable, zero_out_page},
        xhci::XHCIError,
    },
    memory::{
        frame_allocator::{alloc_frame, dealloc_frame},
        KERNEL_MAPPER,
    },
};
use bitflags::bitflags;
use smoltcp::{
    phy::{self, DeviceCapabilities, Medium},
    time::Instant,
    wire::EthernetAddress,
};

use super::{
    context::{EndpointContext, InputControlContext},
    ring_buffer::{ProducerRingBuffer, RingType, TransferRequestBlock, TrbTypes},
    update_deque_ptr, wait_for_events_including_command_completion,
    USBDeviceConfigurationDescriptor, USBDeviceEndpointDescriptor, USBDeviceInfo,
    USBDeviceInterfaceDescriptor, XHCI,
};
use alloc::{slice, str, vec::Vec};
use x86_64::{
    structures::paging::{OffsetPageTable, Page},
    VirtAddr,
};

bitflags! {
    pub struct TRBFlags: u32 {
        const EvaluateNextTrb = 1 << 1;
        const InterruptOnShortPacket = 1 << 2;
        const NoSnoop = 1 << 3;
        const ChainBit = 1 << 4;
        const InterruptOnCompletion = 1 << 5;
        const ImmedateData = 1 << 6;
        const BlockEventInterrupt = 1 << 9;
        const _ = !0;
    }
}

#[repr(u8)]
#[allow(dead_code)]
/// Different type of USB descriptors
enum USBDescriptorTypes {
    Device = 0x1,
    Configuration = 0x2,
    String = 0x3,
    Interface = 0x4,
    Endpoint = 0x5,
    DeviceQualifier = 0x6,
    OtherSpeedConfiguration = 0x7,
    InterfacePower = 0x8,
    CsInterface = 0x24,
    CsEndpoint = 0x25,
}

#[repr(u8)]
#[allow(dead_code)]
/// See Communications Class Subclass Codes (CDC1.2 Section 4.3)
enum CDCSubTypes {
    Header = 0x00,
    Union = 0x06,
    CountrySelection = 0x07,
    EthernetNetwoking = 0x0F,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// A descriptor for a device fonction
struct DeviceFunctionalDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_descriptor_subtype: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// A descriptor for an ethernet networking function
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
/// All of the types of descriptors that an ECM device uses
enum ECMDeviceDescriptors {
    Configuration(USBDeviceConfigurationDescriptor),
    Interface(USBDeviceInterfaceDescriptor),
    Endpoint(USBDeviceEndpointDescriptor),
    Ethernet(EthernetNetworkingFunctionalDescriptor),
}

/// A structure for an ECM USB device
pub struct ECMDevice {
    /// The generic USB device struct
    standard_device: USBDeviceInfo,
    /// A vector for the descriptors for this device
    descriptors: Vec<ECMDeviceDescriptors>,
    /// The address of where recieved data is written to
    recv_addr: VirtAddr,
    /// The endpoint if of the recieve endpoint
    recv_endpoint_id: u32,
    /// The transfer ring buffer for recieves, tells Device that
    /// we want to recieve data, and where to put it
    recv_trb: ProducerRingBuffer,
    /// The address of where transmitted data is read from
    tx_addr: VirtAddr,
    /// The transfer ring buffer for trannsmits, tells Device that
    /// we want to transmit data, and where to get it
    tx_trb: ProducerRingBuffer,
    /// The endpoint id of the transit endpoint
    tx_endpoint_id: u32,
    /// If we are sending out data, and should not send out another packet
    sending_data_out: bool,
}

pub struct ECMDeviceRxToken<'a> {
    in_data_addr: VirtAddr,
    _phantom: PhantomData<&'a *const ()>,
}

impl phy::RxToken for ECMDeviceRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let in_ptr: *mut u8 = self.in_data_addr.as_mut_ptr();
        let in_buf = unsafe { slice::from_raw_parts_mut(in_ptr, 1512) };
        f(in_buf)
    }
}

pub struct ECMDeviceTxToken<'a> {
    out_data_addr: VirtAddr,
    out_trb: &'a mut ProducerRingBuffer,
    slot: u8,
    endpoint_id: u32,
}

impl phy::TxToken for ECMDeviceTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        compile_error!("This code should not be generated");
        let out_ptr: *mut u8 = self.out_data_addr.as_mut_ptr();
        let out_buf = unsafe { slice::from_raw_parts_mut(out_ptr, len) };
        let result = f(out_buf);

        let mapper = KERNEL_MAPPER.lock();

        let transfer_length: u16 = len.try_into().unwrap();
        let transfer_size: u8 = 1;
        let interrupter_target = self.slot;
        let flags = TRBFlags::InterruptOnCompletion | TRBFlags::BlockEventInterrupt;
        let block = TransferRequestBlock {
            parameters: self.out_data_addr.as_u64() - mapper.phys_offset().as_u64(),
            status: (transfer_length as u32)
                | ((transfer_size as u32) << 17)
                | ((interrupter_target as u32) << 22),
            control: flags.bits() | ((TrbTypes::Normal as u32) << 10),
        };
        unsafe {
            self.out_trb.enqueue(block).unwrap();
        }
        drop(mapper);
        let info = XHCI.lock().clone().unwrap();

        let doorbell_base: *mut u32 = (info.base_address.as_u64()
            + info.capablities.doorbell_offset as u64
            + (self.slot as u64) * 4) as *mut u32;
        unsafe { core::ptr::write_volatile(doorbell_base, self.endpoint_id) };

        result
    }
}

impl phy::Device for ECMDevice {
    type RxToken<'a>
        = ECMDeviceRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = ECMDeviceTxToken<'a>
    where
        Self: 'a;
    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Check if there is any data

        let mapper = KERNEL_MAPPER.lock();

        let transfer_length: u16 = 4096;
        let transfer_size: u8 = 1;
        let interrupter_target: u8 = self.standard_device.slot;
        let flags = TRBFlags::InterruptOnCompletion;
        let block = TransferRequestBlock {
            parameters: self.recv_addr.as_u64() - mapper.phys_offset().as_u64(),
            status: (transfer_length as u32)
                | ((transfer_size as u32) << 17)
                | ((interrupter_target as u32) << 22),
            control: flags.bits() | ((TrbTypes::Normal as u32) << 10),
        };
        unsafe { self.recv_trb.enqueue(block).ok()? };
        let info = XHCI.lock().clone().unwrap();

        let doorbell_base: *mut u32 = (info.base_address.as_u64()
            + info.capablities.doorbell_offset as u64
            + (self.standard_device.slot as u64) * 4)
            as *mut u32;
        unsafe { core::ptr::write_volatile(doorbell_base, 5) };
        drop(info);
        let mut event = self.dequeue_event(&mapper)?;
        let mut event_endpoint = (event.control >> 16) & 0xF;
        while event_endpoint & 1 != 1 {
            // Odd endpoint numbers are for the input
            // We got an out probally, so we can safely send more data out (probally)
            self.sending_data_out = false;
            event = self.dequeue_event(&mapper)?;
            event_endpoint = (event.control >> 16) & 0xF;
        }
        drop(mapper);

        let tx_token = ECMDeviceTxToken {
            out_data_addr: self.tx_addr,
            slot: self.standard_device.slot,
            out_trb: &mut self.tx_trb,
            endpoint_id: self.tx_endpoint_id,
        };
        let rx_token = ECMDeviceRxToken {
            in_data_addr: self.recv_addr,
            _phantom: PhantomData,
        };

        let mapper = KERNEL_MAPPER.lock();

        let transfer_length: u16 = 4096;
        let transfer_size: u8 = 1;
        let interrupter_target: u8 = self.standard_device.slot;
        let flags = TRBFlags::InterruptOnCompletion;
        let block = TransferRequestBlock {
            parameters: self.recv_addr.as_u64() - mapper.phys_offset().as_u64(),
            status: (transfer_length as u32)
                | ((transfer_size as u32) << 17)
                | ((interrupter_target as u32) << 22),
            control: flags.bits() | ((TrbTypes::Normal as u32) << 10),
        };
        let _ = unsafe { self.recv_trb.enqueue(block).ok()? };
        drop(mapper);
        let info = XHCI.lock().clone().unwrap();

        let doorbell_base: *mut u32 = (info.base_address.as_u64()
            + info.capablities.doorbell_offset as u64
            + (self.standard_device.slot as u64) * 4)
            as *mut u32;
        unsafe { core::ptr::write_volatile(doorbell_base, self.tx_endpoint_id) };
        drop(info);
        Some((rx_token, tx_token))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.sending_data_out {
            return Option::None;
        }
        self.sending_data_out = true;
        Some(ECMDeviceTxToken {
            out_data_addr: self.tx_addr,
            slot: self.standard_device.slot,
            out_trb: &mut self.tx_trb,
            endpoint_id: self.tx_endpoint_id,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

impl ECMDevice {
    pub fn dequeue_event(&mut self, mapper: &OffsetPageTable<'_>) -> Option<TransferRequestBlock> {
        // first get the result from the ring and return none if there was an err
        let event_result = unsafe { self.standard_device.event_ring.dequeue() };
        if event_result.is_err() {
            return Option::None;
        }

        // get the event and correctly update the dequeue pointers of corresponding transfer rings.
        let event = event_result.ok()?;
        let endpoint_id = (event.control >> 16) & 0x1F;
        let new_dequeue = event.parameters + mapper.phys_offset().as_u64() + 0x10;
        if endpoint_id == self.recv_endpoint_id {
            self.recv_trb
                .set_dequeue(new_dequeue)
                .expect("Should not see this because addr is aligned");
        } else if endpoint_id == self.tx_endpoint_id {
            self.tx_trb
                .set_dequeue(new_dequeue)
                .expect("Should not see this because addr is aligned");
        }

        // update hardware event dequeue pointer register
        let binding = XHCI.lock();
        let info = binding.as_ref().unwrap();
        let erdp_addr = info.base_address
            + info.capablities.runtime_register_space_offset as u64
            + 0x38
            + (32 * self.standard_device.slot as u64);
        unsafe {
            update_deque_ptr(
                erdp_addr.as_mut_ptr(),
                &self.standard_device.event_ring,
                mapper,
            );
        }

        Some(event)
    }

    pub fn get_eth_addr(&mut self) -> Result<EthernetAddress, XHCIError> {
        // self.descriptors
        // Find string descriptor
        let eth_descriptor = self
            .get_ethernet_descriptor()
            .ok_or(XHCIError::NoDescriptor)?;
        let data_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
        let mut mapper = KERNEL_MAPPER.lock();
        let data_addr = mmio::map_page_as_uncacheable(data_frame.start_address(), &mut mapper)
            .map_err(|_| XHCIError::MemoryAllocationFailure)?;
        drop(mapper);
        let bm_request_type: u8 = 0b10000000;
        let b_request: u8 = 6; // Get descriptor
        let descriptor_type: u8 = 3; // string decriptor
        let descriptor_idx: u8 = eth_descriptor.imac_address;
        let w_value: u16 = ((descriptor_type as u16) << 8) | (descriptor_idx as u16);
        let w_idx: u16 = 0x09; // English language id
        let w_length: u16 = 1024;
        let paramaters: u64 = ((w_length as u64) << 48)
            | ((w_idx as u64) << 32)
            | ((w_value as u64) << 16)
            | ((b_request as u64) << 8)
            | (bm_request_type as u64);

        self.standard_device
            .send_command(paramaters, data_frame.start_address(), 1024)
            .unwrap();
        let mut eth_data_str: [u8; 12] = [0; 12];
        let mut eth_str_idx = 0;
        for str_idx in 0..=24 {
            let data_pointer: *const u8 = (data_addr + str_idx).as_ptr();
            let value = unsafe { core::ptr::read_volatile(data_pointer) };
            if value >= 48 {
                eth_data_str[eth_str_idx] = value;
                eth_str_idx += 1;
            }
        }
        let mut eth_data: [u8; 6] = [0; 6];
        for idx in 0..6 {
            let new_string = str::from_utf8(&eth_data_str[(2 * idx)..=((2 * idx) + 1)]).unwrap();
            eth_data[idx] = u8::from_str_radix(new_string, 16).unwrap();
        }

        dealloc_frame(data_frame);
        Result::Ok(EthernetAddress::from_bytes(&eth_data))
    }

    fn get_ethernet_descriptor(&self) -> Option<&EthernetNetworkingFunctionalDescriptor> {
        for descriptor in &self.descriptors {
            if let ECMDeviceDescriptors::Ethernet(eth_descriptor) = descriptor {
                return Option::Some(eth_descriptor);
            }
        }
        Option::None
    }
}

const CLASS_CODE_CDC: u8 = 2;
const CLASS_CODE_CDC_DATA: u8 = 0xA;
const SUBCLASS_CODE_ECM: u8 = 6;

/// Finds the first CDC device.
///
/// Returns:
///     None: If no cdc device with a subclass code of ECM was found
///     Slot, config: The slot and config of the cdc device if the device
///     was found.
pub fn find_cdc_device(devices: &mut Vec<USBDeviceInfo>) -> Option<(u8, u8)> {
    for device in devices {
        if device.descriptor.b_device_class == CLASS_CODE_CDC {
            for configuration in 0..device.descriptor.b_num_configurations {
                let class_desc =
                    get_class_descriptors_for_configuration(device, configuration).unwrap();
                let mut configuration_to_get = 0;

                for descriptor in class_desc {
                    match descriptor {
                        ECMDeviceDescriptors::Interface(config) => {
                            if config.b_interface_class == CLASS_CODE_CDC
                                && config.b_interface_sub_class == SUBCLASS_CODE_ECM
                            {
                                // debug_println!("Configuration = {configuration_to_get}");
                                return Option::Some((device.slot, configuration_to_get));
                            }
                        }
                        ECMDeviceDescriptors::Configuration(config) => {
                            configuration_to_get = config.b_configuration_value;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Option::None
}

/// Finds the interface with multiple endpoints.
///
/// Returns:
///     None: If there was no interface with 2 endpoint
///         This excludes the command endpoint
///     Interface_number, alternate_setting: The interface number and setting
///     of the endpoint
fn find_active_interface(descriptors: &Vec<ECMDeviceDescriptors>) -> Option<(u8, u8)> {
    for descriptor in descriptors {
        if let ECMDeviceDescriptors::Interface(config) = descriptor {
            if config.b_num_endpoints == 2 {
                return Option::Some((config.b_interface_number, config.b_alternate_setting));
            }
        }
    }
    Option::None
}

/// Finds the device context number associated with the input endpoint
fn find_device_context_input(descriptors: &Vec<ECMDeviceDescriptors>) -> Option<u8> {
    let mut valid_interface = false;
    for descriptor in descriptors {
        match descriptor {
            ECMDeviceDescriptors::Interface(config) => {
                valid_interface =
                    config.b_interface_class == CLASS_CODE_CDC_DATA && config.b_num_endpoints == 2;
            }
            ECMDeviceDescriptors::Endpoint(config) => {
                if valid_interface && (config.b_endpoint_address & (1 << 7)) == (1 << 7) {
                    return Option::Some(((config.b_endpoint_address & 0xF) * 2) + 1);
                }
            }
            _ => {}
        }
    }
    Option::None
}
/// Finds the device context number assocciated with the output endpoint
fn find_device_context_output(descriptors: &Vec<ECMDeviceDescriptors>) -> Option<u8> {
    let mut valid_interface = false;
    for descriptor in descriptors {
        match descriptor {
            ECMDeviceDescriptors::Interface(config) => {
                valid_interface =
                    config.b_interface_class == CLASS_CODE_CDC_DATA && config.b_num_endpoints == 2;
            }
            ECMDeviceDescriptors::Endpoint(config) => {
                if valid_interface && (config.b_endpoint_address & (1 << 7)) == (1 << 7) {
                    return Option::Some((config.b_endpoint_address & 0xF) * 2);
                }
            }
            _ => {}
        }
    }
    Option::None
}

pub fn init_cdc_device(
    mut device: USBDeviceInfo,
    configuration: u8,
) -> Result<ECMDevice, XHCIError> {
    // Send Set configuration request to the device
    let bm_request_type: u8 = 0b00000000;
    let b_request: u8 = 9; // Set configuration
    let w_value: u16 = configuration as u16;
    let w_idx: u16 = 0;
    let w_length: u16 = 0;
    let paramaters: u64 = ((w_length as u64) << 48)
        | ((w_idx as u64) << 32)
        | ((w_value as u64) << 16)
        | ((b_request as u64) << 8)
        | (bm_request_type as u64);
    device.send_command_no_data(paramaters)?;

    let descriptors = get_class_descriptors_for_configuration(&mut device, configuration).unwrap();
    let interface = find_active_interface(&descriptors).ok_or(XHCIError::NoInterface)?;
    // Set our interface into the correct alternate interface
    let bm_request_type: u8 = 0b00000001;
    let b_request: u8 = 11; // Set interface
    let w_value: u16 = interface.1 as u16; // Alternate setting
    let w_idx: u16 = interface.0 as u16; // Interface number
    let w_length: u16 = 0;
    let paramaters: u64 = ((w_length as u64) << 48)
        | ((w_idx as u64) << 32)
        | ((w_value as u64) << 16)
        | ((b_request as u64) << 8)
        | (bm_request_type as u64);
    device.send_command_no_data(paramaters)?;

    // Send configure endpoint to XHCI so stuff works
    let context_ptr: *mut InputControlContext = device.input_context_vaddr.as_mut_ptr();
    let mut context = unsafe { core::ptr::read_volatile(context_ptr) };
    let input_id =
        find_device_context_input(&descriptors).expect("ECM should have input endpoint") as u32;
    let output_id =
        find_device_context_output(&descriptors).expect("ECM should have output endpoint") as u32;

    context.set_add_flag(0, 1);
    context.set_add_flag(1, 0);
    context.set_add_flag(input_id, 1);
    context.set_add_flag(output_id, 1);

    let ep_2_context_out_addr = device.input_context_vaddr + 0xA0;
    let ep2_ctxt_out_ptr: *mut EndpointContext = ep_2_context_out_addr.as_mut_ptr();
    let mut ep2_ctxt_out = unsafe { core::ptr::read_volatile(ep2_ctxt_out_ptr) };
    ep2_ctxt_out.set_cerr(3);
    ep2_ctxt_out.set_eptype(2);
    ep2_ctxt_out.set_max_packet_size(64);
    ep2_ctxt_out.set_dcs(1);
    // Now setup context in
    let ep_2_context_in_addr = device.input_context_vaddr + 0xC0;
    let ep2_ctxt_in_ptr: *mut EndpointContext = ep_2_context_in_addr.as_mut_ptr();
    let mut ep2_ctxt_in = unsafe { core::ptr::read_volatile(ep2_ctxt_in_ptr) };
    ep2_ctxt_in.set_cerr(3);
    ep2_ctxt_in.set_eptype(6);
    ep2_ctxt_in.set_max_packet_size(64);
    ep2_ctxt_in.set_dcs(1);
    ep2_ctxt_in.set_average_trb_len(1_600);
    // Set up TRB

    let input_trb_buffer = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let mut mapper = KERNEL_MAPPER.lock();
    let input_trb_address = map_page_as_uncacheable(input_trb_buffer.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    zero_out_page(Page::containing_address(input_trb_address));
    let in_trb = ProducerRingBuffer::new(
        input_trb_buffer.start_address(),
        1,
        RingType::Transfer,
        (PAGE_SIZE).try_into().unwrap(),
        mapper.phys_offset(),
    )
    .expect("Everything should be alligned");
    ep2_ctxt_in.set_trdequeue_ptr(input_trb_buffer.start_address().as_u64());

    let output_trb_buffer = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let output_trb_address =
        map_page_as_uncacheable(output_trb_buffer.start_address(), &mut mapper)
            .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    zero_out_page(Page::containing_address(output_trb_address));

    let out_trb = ProducerRingBuffer::new(
        output_trb_buffer.start_address(),
        1,
        RingType::Transfer,
        (PAGE_SIZE).try_into().unwrap(),
        mapper.phys_offset(),
    )
    .expect("Everything should be alligned");
    ep2_ctxt_out.set_trdequeue_ptr(output_trb_buffer.start_address().as_u64());
    unsafe {
        core::ptr::write_volatile(context_ptr, context);
    }
    unsafe {
        core::ptr::write_volatile(ep2_ctxt_in_ptr, ep2_ctxt_in);
    }
    unsafe {
        core::ptr::write_volatile(ep2_ctxt_out_ptr, ep2_ctxt_out);
    }

    unsafe {
        core::ptr::write_volatile(context_ptr, context);
    }

    let big_device: u32 = device.slot.into();
    let block = TransferRequestBlock {
        parameters: (device.input_context_vaddr.as_u64() - mapper.phys_offset().as_u64()),
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
        (info.base_address.as_u64() + info.capablities.doorbell_offset as u64) as *mut u32;
    unsafe { core::ptr::write_volatile(doorbell_base, 0) };
    wait_for_events_including_command_completion(&mut info, &mapper)?;

    drop(mapper);

    // Setup data buffers for input and output
    let in_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let mut mapper = KERNEL_MAPPER.lock();
    let in_buff_vaddr = mmio::map_page_as_uncacheable(in_frame.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    mmio::zero_out_page(Page::containing_address(in_buff_vaddr));
    let out_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let out_buff_vaddr = mmio::map_page_as_uncacheable(out_frame.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    mmio::zero_out_page(Page::containing_address(out_buff_vaddr));

    let ecm_device = ECMDevice {
        standard_device: device,
        descriptors,
        recv_addr: in_buff_vaddr,
        tx_addr: out_buff_vaddr,
        recv_trb: in_trb,
        recv_endpoint_id: input_id,
        tx_trb: out_trb,
        tx_endpoint_id: output_id,
        sending_data_out: false,
    };
    Result::Ok(ecm_device)
}

/// Returns the class descriptors for a particular configuration
fn get_class_descriptors_for_configuration(
    device: &mut USBDeviceInfo,
    configuration: u8,
) -> Result<Vec<ECMDeviceDescriptors>, XHCIError> {
    let data_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let mut mapper = KERNEL_MAPPER.lock();
    let data_addr = mmio::map_page_as_uncacheable(data_frame.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    drop(mapper);
    let bm_request_type: u8 = 0b10000000;
    let b_request: u8 = 6; // Get descriptor
    let descriptor_type: u8 = 2; // Configuration
    let descriptor_idx: u8 = configuration;
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
    descriptors.push(ECMDeviceDescriptors::Configuration(config_descriptor));
    let total_size: usize = config_descriptor.w_total_length.into();
    let mut bytes_read: usize = config_descriptor.b_length.into();
    while bytes_read < total_size {
        let desc_vaddr = data_addr + bytes_read.try_into().unwrap();
        let desc_ptr: *const DeviceFunctionalDescriptor = desc_vaddr.as_ptr();
        let base_device = unsafe { core::ptr::read_unaligned(desc_ptr) };
        const INTERFACE: u8 = USBDescriptorTypes::Interface as u8;
        const ENDPOINT: u8 = USBDescriptorTypes::Endpoint as u8;
        const CS_ENDPOINT: u8 = USBDescriptorTypes::CsEndpoint as u8;
        const CS_INTERFACE: u8 = USBDescriptorTypes::CsInterface as u8;
        match base_device.b_descriptor_type {
            INTERFACE => {
                let interface_ptr: *const USBDeviceInterfaceDescriptor = desc_vaddr.as_ptr();
                let interface_descriptor = unsafe { core::ptr::read_unaligned(interface_ptr) };
                descriptors.push(ECMDeviceDescriptors::Interface(interface_descriptor));
            }
            ENDPOINT => {
                let endpoint_ptr: *const USBDeviceEndpointDescriptor = desc_vaddr.as_ptr();
                let endpoint_descriptor = unsafe { core::ptr::read_unaligned(endpoint_ptr) };
                descriptors.push(ECMDeviceDescriptors::Endpoint(endpoint_descriptor));
            }
            CS_ENDPOINT | CS_INTERFACE => {
                if base_device.b_descriptor_subtype == CDCSubTypes::EthernetNetwoking as u8 {
                    let networking_ptr: *const EthernetNetworkingFunctionalDescriptor =
                        desc_vaddr.as_ptr();
                    let networking_desc = unsafe { core::ptr::read_unaligned(networking_ptr) };
                    descriptors.push(ECMDeviceDescriptors::Ethernet(networking_desc));
                }
            }
            _ => {
                panic!("Unreckonised descriptor type")
            }
        }
        bytes_read += base_device.b_length as usize;
    }
    // TODO: When we update the mapper to not have 2mib pages we would want to
    // remove the uncachable flags from the pte, (BUT not unmap the page to
    // keep the idea that the kernel mapper has access to every physical
    // page in memory
    dealloc_frame(data_frame);
    Result::Ok(descriptors)
}
