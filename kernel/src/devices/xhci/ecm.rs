use core::{marker::PhantomData, str};

use crate::{
    constants::memory::PAGE_SIZE,
    debug_println,
    devices::{
        mmio::{self, map_page_as_uncacheable, zero_out_page},
        xhci::XHCIError,
    },
    memory::{frame_allocator::alloc_frame, MAPPER},
};
use smoltcp::{
    iface::{Interface, SocketSet},
    phy::{self, DeviceCapabilities, Medium},
    socket::dhcpv4,
    time::Instant,
    wire::{EthernetAddress, IpCidr, Ipv4Cidr},
};

use super::{
    context::{EndpointContext, InputControlContext},
    ring_buffer::{ProducerRingBuffer, RingType, TransferRequestBlock, TrbTypes},
    wait_for_events_including_command_completion, USBDeviceConfigurationDescriptor,
    USBDeviceDescriptor, USBDeviceEndpointDescriptor, USBDeviceInfo, USBDeviceInterfaceDescriptor,
    XHCI,
};
use alloc::{slice, vec::Vec};
use x86_64::{structures::paging::Page, VirtAddr};

#[repr(u8)]
#[allow(dead_code)]
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
enum CDCSubTypes {
    Header = 0x00,
    Union = 0x06,
    CountrySelection = 0x07,
    EthernetNetwoking = 0x0F,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[allow(dead_code)]
struct DeviceFunctionalDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_descriptor_subtype: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[allow(dead_code)]
struct HeaderFunctionalDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_descriptor_subtype: u8,
    bcd_cdc: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[allow(dead_code)]
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
#[allow(dead_code)]
enum ECMDeviceDescriptors {
    Device(USBDeviceDescriptor),
    Configuration(USBDeviceConfigurationDescriptor),
    Interface(USBDeviceInterfaceDescriptor),
    Endpoint(USBDeviceEndpointDescriptor),
    Functional(DeviceFunctionalDescriptor),
    Ethernet(EthernetNetworkingFunctionalDescriptor),
}

#[allow(dead_code)]
pub struct ECMDevice {
    standard_device: USBDeviceInfo,
    descriptors: Vec<ECMDeviceDescriptors>,
    in_data_addr: VirtAddr,
    out_data_addr: VirtAddr,
    in_data_trb: ProducerRingBuffer,
    out_data_trb: ProducerRingBuffer,
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
        // TODO: Recieve the packet
        // todo!("Recieving is currently broken");

        let in_ptr: *mut u8 = self.in_data_addr.as_mut_ptr();
        let in_buf = unsafe { slice::from_raw_parts_mut(in_ptr, 1512) };
        let result = f(in_buf);

        // let result = f(self.0);
        debug_println!("rx called");
        result
    }
}

pub struct ECMDeviceTxToken<'a> {
    out_data_addr: VirtAddr,
    out_trb: &'a mut ProducerRingBuffer,
    slot: u8,
}

impl phy::TxToken for ECMDeviceTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let out_ptr: *mut u8 = self.out_data_addr.as_mut_ptr();
        let out_buf = unsafe { slice::from_raw_parts_mut(out_ptr, len) };
        let result = f(out_buf);
        debug_println!("tx called {}", len);

        let mapper = MAPPER.lock();

        let transfer_length: u16 = len.try_into().unwrap();
        let transfer_size: u8 = 1;
        let interrupter_target = self.slot;
        let block = TransferRequestBlock {
            parameters: self.out_data_addr.as_u64() - mapper.phys_offset().as_u64(),
            status: (transfer_length as u32)
                | ((transfer_size as u32) << 17)
                | ((interrupter_target as u32) << 22),
            control:  (TrbTypes::Normal as u32) << 10,
        };
        unsafe {
            self.out_trb.enqueue(block).unwrap();
        }
        drop(mapper);
        let info = XHCI.lock().clone().unwrap();

        let doorbell_base: *mut u32 = (info.base_address
            + info.capablities.doorbell_offset as u64
            + (self.slot as u64) * 4) as *mut u32;
        unsafe { core::ptr::write_volatile(doorbell_base, 4) };

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
        // todo!("Recieving is currently broken");
        // Check if there is any data

        let mapper = MAPPER.lock();

        let transfer_length: u16 = 4096;
        let transfer_size: u8 = 1;
        let interrupter_target: u8 = self.standard_device.slot;
        let block = TransferRequestBlock {
            parameters: self.in_data_addr.as_u64() - mapper.phys_offset().as_u64(),
            status: (transfer_length as u32)
                | ((transfer_size as u32) << 17)
                | ((interrupter_target as u32) << 22),
            control: (1 << 5) | ((TrbTypes::Normal as u32) << 10),
        };
        let trb_addr = unsafe { self.in_data_trb.enqueue(block).ok()? };
        drop(mapper);
        let info = XHCI.lock().clone().unwrap();

        let doorbell_base: *mut u32 = (info.base_address
            + info.capablities.doorbell_offset as u64
            + (self.standard_device.slot as u64) * 4)
            as *mut u32;
        unsafe { core::ptr::write_volatile(doorbell_base, 5) };

        let event_result = unsafe { self.standard_device.event_ring.dequeue() };
        if event_result.is_err() {
            return Option::None;
        }

        let mapper = MAPPER.lock();
        let event = event_result.ok()?;
        if event.parameters != trb_addr.as_u64() - mapper.phys_offset().as_u64() - 0x10 {
            // Whoops
            debug_println!(
                "Params = {:X}, addr = {:X}",
                event.parameters,
                trb_addr.as_u64()
            );
            // todo!("Handle this issue");
        }
        drop(mapper);
        // TODO: determine type of event

        // todo!("Reciecing prob borken");
        let tx_token = ECMDeviceTxToken {
            out_data_addr: self.out_data_addr,
            slot: self.standard_device.slot,
            out_trb: &mut self.out_data_trb,
        };
        let rx_token = ECMDeviceRxToken {
            in_data_addr: self.in_data_addr,
            _phantom: PhantomData,
        };
        Some((rx_token, tx_token))
        // Some((
        //     ECMDeviceRxToken(&mut self.rx_buffer[..]),
        //     ECMDeviceTxToken(&mut self.tx_buffer[..]),
        // ))
    }
    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(ECMDeviceTxToken {
            out_data_addr: self.out_data_addr,
            slot: self.standard_device.slot,
            out_trb: &mut self.out_data_trb,
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
                    if let ECMDeviceDescriptors::Interface(config) = descriptor {
                        if config.b_interface_class == CLASS_CODE_CDC
                            && config.b_interface_sub_class == SUBCLASS_CODE_ECM
                        {
                            return Option::Some((device.slot, configuration));
                        }
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
    let w_value: u16 = 1;
    let w_idx: u16 = 0;
    let w_length: u16 = 0;
    let paramaters: u64 = ((w_length as u64) << 48)
        | ((w_idx as u64) << 32)
        | ((w_value as u64) << 16)
        | ((b_request as u64) << 8)
        | (bm_request_type as u64);
    device.send_command_no_data(paramaters)?;

    let bm_request_type: u8 = 0b00000001;
    let b_request: u8 = 11; // Set interface
    let w_value: u16 = 1; // Alternate setting
    let w_idx: u16 = 1; // Interface number
    let w_length: u16 = 0;
    let paramaters: u64 = ((w_length as u64) << 48)
        | ((w_idx as u64) << 32)
        | ((w_value as u64) << 16)
        | ((b_request as u64) << 8)
        | (bm_request_type as u64);
    device.send_command_no_data(paramaters)?;

    let descriptors = get_class_descriptors_for_configuration(&mut device, 1).unwrap();
    debug_println!("class_desc = {descriptors:?}");

    // Send configure endpoint
    // We use endpoint 2, both in and out
    debug_println!("device_slot = {}", device.slot);
    let context_ptr: *mut InputControlContext = device.input_context_vaddr.as_mut_ptr();
    let mut context = unsafe { core::ptr::read_volatile(context_ptr) };

    context.set_add_flag(0, 1);
    context.set_add_flag(1, 0);
    // context.set_drop_flag(0, 0);
    // context.set_drop_flag(1, 0);
    context.set_add_flag(4, 1);
    context.set_add_flag(5, 1);

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
    ep2_ctxt_in.set_trdequeue_ptr(input_trb_buffer.start_address().as_u64());

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
    ep2_ctxt_out.set_trdequeue_ptr(output_trb_buffer.start_address().as_u64());
    debug_println!("EP2 ctxt out ptr = {:X}", ep_2_context_out_addr);
    debug_println!("Deque = {:X}", output_trb_buffer.start_address().as_u64());
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
    for descriptor in &descriptors {
        if let ECMDeviceDescriptors::Ethernet(desc) = descriptor {
            str_addr = desc.imac_address;
        }
    }

    drop(mapper);

    let hw_addr = get_eth_addr(&mut device, str_addr)?;
    let config = get_class_descriptors_for_configuration(&mut device, 1).unwrap();
    debug_println!("class_desc = {config:?}");

    // See if we can send something
    let in_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let mut mapper = MAPPER.lock();
    let in_buff_vaddr = mmio::map_page_as_uncacheable(in_frame.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    mmio::zero_out_page(Page::containing_address(in_buff_vaddr));
    let out_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let out_buff_vaddr = mmio::map_page_as_uncacheable(out_frame.start_address(), &mut mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    mmio::zero_out_page(Page::containing_address(out_buff_vaddr));
    drop(mapper);

    let mut ecm_device = ECMDevice {
        standard_device: device,
        descriptors,
        in_data_addr: in_buff_vaddr,
        out_data_addr: out_buff_vaddr,
        in_data_trb: in_trb,
        out_data_trb: out_trb,
    };
    let config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(hw_addr));
    let mut interface = smoltcp::iface::Interface::new(config, &mut ecm_device, Instant::ZERO);
    let dhcp_socket = dhcpv4::Socket::new();
    let socket_vec = Vec::new();
    let mut sockets = SocketSet::new(socket_vec);
    let dhcp_handle = sockets.add(dhcp_socket);
    interface.poll(Instant::from_micros(1), &mut ecm_device, &mut sockets);
    let event = sockets.get_mut::<dhcpv4::Socket>(dhcp_handle).poll();
    match event {
        None => {}
        Some(dhcpv4::Event::Configured(config)) => {
            debug_println!("DHCP config acquired!");

            debug_println!("IP address:      {}", config.address);
            set_ipv4_addr(&mut interface, config.address);

            if let Some(router) = config.router {
                debug_println!("Default gateway: {}", router);
                interface
                    .routes_mut()
                    .add_default_ipv4_route(router)
                    .unwrap();
            } else {
                debug_println!("Default gateway: None");
                interface.routes_mut().remove_default_ipv4_route();
            }

            for (i, s) in config.dns_servers.iter().enumerate() {
                debug_println!("DNS server {}:    {}", i, s);
            }
        }
        Some(dhcpv4::Event::Deconfigured) => {
            debug_println!("DHCP lost config!");
            interface.update_ip_addrs(|addrs| addrs.clear());
            interface.routes_mut().remove_default_ipv4_route();
        }
    };
    debug_println!("After recv fake frame");
    Result::Err(XHCIError::UnknownPort)
}

fn set_ipv4_addr(iface: &mut Interface, cidr: Ipv4Cidr) {
    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        addrs.push(IpCidr::Ipv4(cidr)).unwrap();
    });
}

fn get_eth_addr(device: &mut USBDeviceInfo, idx: u8) -> Result<EthernetAddress, XHCIError> {
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
        let new_string = str::from_utf8(&eth_data_str[(2 * idx)..((2 * idx) + 1)]).unwrap();
        eth_data[idx] = u8::from_str_radix(new_string, 16).unwrap();
        debug_println!("Eth data[idx] = {:X}", eth_data[idx]);
    }

    Result::Ok(EthernetAddress::from_bytes(&eth_data))
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
                // Interface
                let interface_ptr: *const USBDeviceInterfaceDescriptor = desc_vaddr.as_ptr();
                let interface_descriptor = unsafe { core::ptr::read_unaligned(interface_ptr) };
                descriptors.push(ECMDeviceDescriptors::Interface(interface_descriptor));
            }
            ENDPOINT => {
                // Endpoint
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
    Result::Ok(descriptors)
}
