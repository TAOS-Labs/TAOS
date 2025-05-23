//! Deals with the XHCI controller and XHCI root hub ports
//!
//! XHCI Spec refers to Revision 1.2 found here
//! https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf

pub mod context;
pub mod ecm;
pub mod ring_buffer;

use core::{cmp::min, mem::MaybeUninit};

use crate::{
    constants::memory::PAGE_SIZE,
    debug_println,
    devices::mmio::zero_out_page,
    memory::{
        frame_allocator::{alloc_frame, dealloc_frame},
        KERNEL_MAPPER,
    },
    net::set_interface,
};
use alloc::{sync::Arc, vec::Vec};
use bitflags::bitflags;
use context::{EndpointContext, InputControlContext, SlotContext};
use ecm::{find_cdc_device, init_cdc_device};
use ring_buffer::{
    ConsumerRingBuffer, ProducerRingBuffer, RingType, TransferRequestBlock, TrbTypes,
};
use spin::Mutex;
use x86_64::{
    structures::paging::{mapper::TranslateResult, OffsetPageTable, Page, Translate},
    PhysAddr, VirtAddr,
};

use super::{
    mmio::{self, map_page_as_uncacheable},
    pci::{read_config, DeviceInfo},
};

const MAX_USB_DEVICES: u8 = 8;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
/// See section 5.3 of the xHCI spec
struct XHCICapabilities {
    /// Contains the offset to add to register base to find the beginning of the operational register space
    register_length: u8,
    /// Contains the BCD encoding of the xHCI specification revision number supported by the host controller
    version_number: u16,
    /// Contains the basic structural parameters of the host controller
    structural_paramaters_1: u32,
    /// Defines additional structural parameters of the host controller
    structural_paramaters_2: u32,
    /// Defines link exit latency related structural parameters
    structural_paramaters_3: u32,
    /// Defines optional capabilities supported by the host controller
    capability_paramaters_1: u32,
    /// Defines the offest fo the Doorbell Array base address from the Base
    doorbell_offset: u32,
    /// Defines the offset of the Runtime Registers from the base
    runtime_register_space_offset: u32,
    /// Defines optional capabilities of this host controller
    capability_paramaters_2: u32,
}

#[derive(Debug, Clone)]
/// Contains info for the xHCI
pub struct XHCIInfo {
    /// The base address of the register space for the xHCI
    base_address: VirtAddr,
    /// The capabilities extracted from the capabilities register
    capablities: XHCICapabilities,
    /// The base address of the operational registers
    operational_register_address: u64,
    /// Stores the array of slot contexts
    base_address_array: VirtAddr,
    /// The command ring structure for the xHCI
    command_ring: Arc<Mutex<ProducerRingBuffer>>,
    /// The primary event ring for the xHCI
    primary_event_ring: Arc<Mutex<ConsumerRingBuffer>>,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// A device descriptor describing a USB device
pub struct USBDeviceDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    bcd_usb: u16,
    b_device_class: u8,
    b_device_sub_class: u8,
    b_device_protocol: u8,
    b_max_packet_size_0: u8,
    id_vendor: u16,
    id_product: u16,
    bcd_device: u16,
    i_manufacturer: u8,
    i_product: u8,
    i_serial_number: u8,
    b_num_configurations: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// A descriptor for a device configuration
pub struct USBDeviceConfigurationDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    w_total_length: u16,
    b_num_interfaces: u8,
    b_configuration_value: u8,
    i_configuration: u8,
    bm_attributes: u8,
    b_max_power: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// A descriptor for a device interface
pub struct USBDeviceInterfaceDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_interface_number: u8,
    b_alternate_setting: u8,
    b_num_endpoints: u8,
    b_interface_class: u8,
    b_interface_sub_class: u8,
    b_interface_protocol: u8,
    i_interface: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// A descriptor for a device endpoint
pub struct USBDeviceEndpointDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_endpoint_address: u8,
    bm_attribute: u8,
    w_max_packet_size: u16,
    b_interval: u8,
}

/// Determine type and direction of control transfers (see section 4.11.2.2)
#[allow(dead_code)]
enum TransferType {
    NoDataStage = 0,
    Reserved = 1,
    OutDataStage = 2,
    InDataStage = 3,
}

/// A structure for USB Devices
pub struct USBDeviceInfo {
    descriptor: USBDeviceDescriptor,
    command_ring: ProducerRingBuffer,
    event_ring: ConsumerRingBuffer,
    input_context_vaddr: VirtAddr,
    slot: u8,
}

impl USBDeviceInfo {
    /// Sends a command on the Command ring
    pub fn send_command(
        &mut self,
        setup_params: u64,
        data_addr: PhysAddr,
        data_addr_size: usize,
    ) -> Result<(), XHCIError> {
        assert!(data_addr_size < u16::MAX.into());
        let transfer_length: u16 = 8;
        let info = XHCI.lock().clone().unwrap();

        let setup_trb = TransferRequestBlock {
            parameters: setup_params,
            status: transfer_length as u32,
            control: (1 << 6)
                | ((TrbTypes::SetupStage as u32) << 10)
                | ((TransferType::InDataStage as u32) << 16),
        };
        unsafe {
            self.command_ring
                .enqueue(setup_trb)
                .map_err(|_| XHCIError::TransferRingError)?;
        }

        let transfer_length: u16 = data_addr_size.try_into().expect("Asserted would fit");
        let td_size: u8 = 0;
        let data_trb = TransferRequestBlock {
            parameters: data_addr.as_u64(),
            status: ((td_size as u32) << 17) | transfer_length as u32,
            control: (1 << 16) | ((TrbTypes::DataStage as u32) << 10),
        };

        unsafe {
            self.command_ring
                .enqueue(data_trb)
                .map_err(|_| XHCIError::TransferRingError)?;
        }
        let interrupter_target: u32 = self.slot.into();
        let status_trb = TransferRequestBlock {
            parameters: 0,
            status: interrupter_target << 22,
            control: ((TrbTypes::StatusStage as u32) << 10) | (1 << 5),
        };

        unsafe {
            self.command_ring
                .enqueue(status_trb)
                .map_err(|_| XHCIError::TransferRingError)?;
        }
        let doorbell_base: *mut u32 = (info.base_address.as_u64()
            + info.capablities.doorbell_offset as u64
            + (self.slot as u64) * 4) as *mut u32;
        unsafe { core::ptr::write_volatile(doorbell_base, 1) };
        let mapper = &mut KERNEL_MAPPER.lock();
        wait_for_events(&info, &mut self.event_ring, self.slot.into(), mapper)?;
        Ok(())
    }

    pub fn send_command_no_data(&mut self, setup_params: u64) -> Result<(), XHCIError> {
        let transfer_length: u16 = 8;
        let info = XHCI.lock().clone().unwrap();

        let setup_trb = TransferRequestBlock {
            parameters: setup_params,
            status: transfer_length as u32,
            control: (1 << 6)
                | ((TrbTypes::SetupStage as u32) << 10)
                | ((TransferType::InDataStage as u32) << 16),
        };
        unsafe {
            self.command_ring
                .enqueue(setup_trb)
                .map_err(|_| XHCIError::TransferRingError)?;
        }
        let interrupter_target: u32 = self.slot.into();
        let status_trb = TransferRequestBlock {
            parameters: 0,
            status: interrupter_target << 22,
            control: ((TrbTypes::StatusStage as u32) << 10) | (1 << 5),
        };

        unsafe {
            self.command_ring
                .enqueue(status_trb)
                .map_err(|_| XHCIError::TransferRingError)?;
        }
        let doorbell_base: *mut u32 = (info.base_address.as_u64()
            + info.capablities.doorbell_offset as u64
            + (self.slot as u64) * 4) as *mut u32;
        unsafe { core::ptr::write_volatile(doorbell_base, 1) };
        let mapper = &mut KERNEL_MAPPER.lock();
        wait_for_events(&info, &mut self.event_ring, self.slot.into(), mapper)?;

        Ok(())
    }
}

#[derive(Debug)]
/// Different types of errors that can occur in the xHCI
pub enum XHCIError {
    MemoryAllocationFailure,
    NoFrameAllocator,
    UnknownPort,
    CommandRingError,
    TransferRingError,
    Timeout,
    NoInterface,
    NoDescriptor,
}

bitflags! {
    /// See section 5.4.1 of the xHCI spec
    #[derive(Debug, Clone, Copy)]
    struct CommandRegister: u32 {
        /// Set to true to run or false to stop
        const RunHostControler = 1;
        /// Set to true to reset the host controller (HC)
        const HostConterReset = 1 << 1;
        /// Set to true to allow the HC to send interrupts
        const InterrupterEnable = 1 << 2;
        /// Set to true to allow the HC to assert an out-of-band error when the HSE bit in the USBSTS Register is true
        const HostSystemErrorEnable = 1 << 3;
        /// Set to true to be able to reset the HC without losing the state of the ports
        const LightHostControllerReset = 1 << 7;
        /// Set to true to save the internal state of the controller
        const ControllerSaveState = 1 << 8;
        /// Set to true to restore saved internal state of the controller
        const ControllerRestoreState = 1 << 9;
        const _ = !0;
    }
}

bitflags! {
    /// See section 5.4.2 of the XHCI spec
    #[derive(Debug, Clone, Copy)]
    struct StatusRegister: u32 {
        /// When this bit is true, the HC will not send or recieve packets
        const HCHalted = 1;
        /// When this bit is true, the HC encountered a serious error
        const HostSytemError = 1 << 2;
        /// The xHC sets this bit to 1 when the interrupt pending (IP) bit of any interrupter transitions from 0 to 1
        const EventInterrupt = 1 << 3;
        /// The xHC sets this bit to 1 when the when any port has a change bit transition from a 0 to 1
        const PortChangeDetect = 1 << 4;
        /// When this bit is 0 the HC is ready
        const ControllerNotReady = 1 << 11;
        /// The HC will set this flag when there is an internal error
        const HostControllerError = 1 << 12;
        const _ = !0;
    }
}

bitflags! {
    /// See Section 5.4.8 of the XHCI spec (PORTSC)
    #[derive(Debug, Clone, Copy)]
    struct PortStatusAndControl: u32 {
        //. Read Only, 1 = device connected (CCS)
        const CurrentConnectStatus = 1;
        /// 1 = enabled, 0 = disabled, disable by writing 1 (PED)
        const PortEnabled = 1 << 1;
        /// Set to 1 to reset the port (PR)
        const PortReset = 1 << 4;
        const _ = !0;
    }
}

#[allow(dead_code)]
/// The link state of the port
/// see Table 5.27 Port Status and Control Register Bit Definition
enum PortLinkStateRead {
    U0 = 0,
    U1 = 1,
    U2 = 2,
    DeviceSuspended = 3,
    Disabled = 4,
    RxDetect = 5,
    Inactive = 6,
    Polling = 7,
    Recovery = 8,
    HotReset = 9,
    ComplianceMode = 10,
    TestMode = 11,
    Resume = 15,
}

pub static XHCI: Mutex<Option<XHCIInfo>> = Mutex::new(Option::None);

const XHCI_CLASS_CODE: u8 = 0x0C;
const XHCI_SUB_CLASS_CODE: u8 = 0x03;
const XHCI_PROGRAMMING_INTERFACE: u8 = 0x30;

/// Finds the FIRST device that represents an XHCI device
pub fn find_xhci_inferface(
    devices: &Vec<Arc<Mutex<DeviceInfo>>>,
) -> Option<Arc<Mutex<DeviceInfo>>> {
    for possible_device in devices {
        let arc_device = possible_device.clone();
        let device = arc_device.lock();
        if device.class_code == XHCI_CLASS_CODE
            && device.subclass == XHCI_SUB_CLASS_CODE
            && device.programming_interface == XHCI_PROGRAMMING_INTERFACE
        {
            return Option::Some(possible_device.clone());
        }
    }
    Option::None
}

/// Initalizes an xhci_hub
pub fn initalize_xhci_hub(device: &Arc<Mutex<DeviceInfo>>) -> Result<(), XHCIError> {
    let mut mapper = KERNEL_MAPPER.lock();
    let device_lock = device.clone();
    let xhci_device = device_lock.lock();
    let bar_0: u64 =
        (read_config(xhci_device.bus, xhci_device.device, 0, 0x10) & 0xFFFFFFF0).into();
    let bar_1: u64 = read_config(xhci_device.bus, xhci_device.device, 0, 0x14).into();
    let full_bar = (bar_1 << 32) | bar_0;

    let mut info = initalize_xhci_info(full_bar, &mut mapper)?;
    // Turn on device

    run_host_controller(&info);
    let mut devices = boot_up_all_ports(&mut info, &mut mapper)?;
    let mut val = XHCI.lock();
    *val = Option::Some(info);
    drop(val);
    drop(mapper);
    for device in &mut devices {
        let mut mapper = KERNEL_MAPPER.lock();
        let data_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
        let data_addr = mmio::map_page_as_uncacheable(data_frame.start_address(), &mut mapper)
            .map_err(|_| XHCIError::MemoryAllocationFailure)?;
        drop(mapper);
        let bm_request_type: u8 = 0b10000000;
        let b_request: u8 = 6; // Get descriptor
        let descriptor_type: u8 = 1; // Device
        let descriptor_idx: u8 = 0; // Unused with Device descriptor type
        let w_value: u16 = ((descriptor_type as u16) << 8) | (descriptor_idx as u16);
        let w_idx: u16 = 0;
        let w_length: u16 = 18;
        device.send_command(
            ((w_length as u64) << 48)
                | ((w_idx as u64) << 32)
                | ((w_value as u64) << 16)
                | ((b_request as u64) << 8)
                | (bm_request_type as u64),
            data_frame.start_address(),
            1024,
        )?;
        // We have the descriptor at the start of the adddress
        let descriptor_ptr: *const USBDeviceDescriptor = data_addr.as_ptr();
        device.descriptor = unsafe { core::ptr::read_volatile(descriptor_ptr) };
        dealloc_frame(data_frame);
    }
    // Now look for devices
    let slot_config = find_cdc_device(&mut devices).unwrap();
    let slot = slot_config.0;
    let configuration = slot_config.1;
    let mut device = init_cdc_device(
        find_device_in_slot(&mut devices, slot).expect("Found device should be in list of devices"),
        configuration,
    )?;
    let hw_address = device.get_eth_addr()?;
    set_interface(device, hw_address);
    Result::Ok(())
}

fn find_device_in_slot(devices: &mut Vec<USBDeviceInfo>, slot: u8) -> Option<USBDeviceInfo> {
    for device_idx in 0..devices.len() {
        let device = &devices[device_idx];
        if device.slot == slot {
            return Option::Some(devices.remove(device_idx));
        }
    }
    Option::None
}

/// Tells the host controller to start running by setting the RunHostControler
/// bitflag to true
fn run_host_controller(info: &XHCIInfo) {
    let command_register_address = info.operational_register_address as *mut u32;
    let mut command_data = CommandRegister::from_bits_retain(unsafe {
        core::ptr::read_volatile(command_register_address)
    });
    command_data = command_data.union(CommandRegister::RunHostControler);
    unsafe {
        core::ptr::write_volatile(command_register_address, command_data.bits());
    }
}

/// Determines the capablities of a given host controller
fn get_host_controller_cap_regs(address: u64) -> XHCICapabilities {
    let register_length_addr = (address) as *const u8;
    let register_length = unsafe { core::ptr::read_volatile(register_length_addr) };

    let version_no_addr = (address + 0x2) as *const u16;
    let version_no = unsafe { core::ptr::read_volatile(version_no_addr) };

    let hcs_params_1_addr = (address + 0x4) as *const u32;
    let hcs_params_1 = unsafe { core::ptr::read_volatile(hcs_params_1_addr) };
    let hcs_params_2_addr = (address + 0x8) as *const u32;
    let hcs_params_2 = unsafe { core::ptr::read_volatile(hcs_params_2_addr) };
    let hcs_params_3_addr = (address + 0xC) as *const u32;
    let hcs_params_3 = unsafe { core::ptr::read_volatile(hcs_params_3_addr) };

    let cap_params_1_addr = (address + 0x10) as *const u32;
    let cap_params_1 = unsafe { core::ptr::read_volatile(cap_params_1_addr) };

    let doorbell_addr = (address + 0x14) as *const u32;
    let doorbell_offset = unsafe { core::ptr::read_volatile(doorbell_addr) };
    let runtime_register_addr = (address + 0x18) as *const u32;
    let runtime_register_offset = unsafe { core::ptr::read_volatile(runtime_register_addr) };

    let cap_params_2_addr = (address + 0x18) as *const u32;
    let cap_params_2 = unsafe { core::ptr::read_volatile(cap_params_2_addr) };
    XHCICapabilities {
        register_length,
        version_number: version_no,
        structural_paramaters_1: hcs_params_1,
        structural_paramaters_2: hcs_params_2,
        structural_paramaters_3: hcs_params_3,
        capability_paramaters_1: cap_params_1,
        doorbell_offset,
        runtime_register_space_offset: runtime_register_offset,
        capability_paramaters_2: cap_params_2,
    }
}

/// Runs a software reset of the xchi controller, TODO: Make asnyc
fn reset_xchi_controller(operational_registers: u64) {
    let command_register_address = operational_registers as *mut u32;
    let mut command_data = CommandRegister::from_bits_retain(unsafe {
        core::ptr::read_volatile(command_register_address)
    });
    // Turn off the host controller
    command_data.remove(CommandRegister::RunHostControler);
    unsafe {
        core::ptr::write_volatile(command_register_address, command_data.bits());
    }
    // Wait for it to take
    let status_register_address = (operational_registers + 0x4) as *mut u32;
    let mut status_data = StatusRegister::from_bits_retain(unsafe {
        core::ptr::read_volatile(status_register_address)
    });
    while !StatusRegister::HCHalted.intersects(status_data) {
        status_data = StatusRegister::from_bits_retain(unsafe {
            core::ptr::read_volatile(status_register_address)
        });
        core::hint::spin_loop();
    }
    // HCH halted, start reset procedure
    command_data = command_data.union(CommandRegister::HostConterReset);
    unsafe {
        core::ptr::write_volatile(command_register_address, command_data.bits());
    }
    while CommandRegister::HostConterReset.intersects(command_data) {
        command_data = CommandRegister::from_bits_retain(unsafe {
            core::ptr::read_volatile(command_register_address)
        });
        core::hint::spin_loop();
    }
    // Everything reset, wait for controllernot ready to be unset
    while StatusRegister::ControllerNotReady.intersects(status_data) {
        status_data = StatusRegister::from_bits_retain(unsafe {
            core::ptr::read_volatile(status_register_address)
        });
        core::hint::spin_loop();
    }
}

fn initalize_xhci_info(full_bar: u64, mapper: &mut OffsetPageTable) -> Result<XHCIInfo, XHCIError> {
    let base_virtual_address =
        mmio::map_page_as_uncacheable(PhysAddr::new(full_bar), mapper).unwrap();
    let capablities = get_host_controller_cap_regs(base_virtual_address.as_u64());
    let extended_reg_length: u64 = capablities.register_length.into();
    let operational_start = base_virtual_address.as_u64() + extended_reg_length;
    reset_xchi_controller(operational_start);

    // Program max device device slots
    let config_reg_addr = (operational_start + 0x38) as *mut u32;
    // Extract the max device slots from the capability parameters 1 register
    let mut max_devices: u32 = capablities.capability_paramaters_1 & 0xFF;
    max_devices = min(max_devices, MAX_USB_DEVICES.into());
    unsafe { core::ptr::write_volatile(config_reg_addr, max_devices) }
    // Allocate space for DCBAAP (Device Context Base Array Pointer Register)
    let dcbaap_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let virtual_adddr = mmio::map_page_as_uncacheable(dcbaap_frame.start_address(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    // We need to zero out shit
    mmio::zero_out_page(Page::containing_address(virtual_adddr));

    // set DCBAAP (Device Context Base Array Pointer Register)
    let dcbaap_reg_addr = (operational_start + 0x30) as *mut u64;
    unsafe {
        core::ptr::write_volatile(dcbaap_reg_addr, dcbaap_frame.start_address().as_u64());
    }

    // Allocate space for the Command Ring.
    let cmd_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let cmd_vaddr = mmio::map_page_as_uncacheable(cmd_frame.start_address(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;

    // We need to zero out this page as well
    let cmd_page: Page = Page::containing_address(cmd_vaddr);
    mmio::zero_out_page(cmd_page);

    // set Command Ring Control reg to starting addr of command ring.
    let crcreg_addr = (operational_start + 0x18) as *mut u64;
    let crcreg_value = cmd_frame.start_address().as_u64() | 1;
    unsafe {
        core::ptr::write_volatile(crcreg_addr, crcreg_value);
    }

    // create the command ring data structure.
    let command_ring = ProducerRingBuffer::new(
        cmd_frame.start_address(),
        1,
        ring_buffer::RingType::Command,
        PAGE_SIZE.try_into().unwrap(),
        mapper.phys_offset(),
    )
    .expect("Error initializing producer ring.");

    mmio::map_page_as_uncacheable(
        PhysAddr::new(full_bar + (capablities.runtime_register_space_offset as u64)),
        mapper,
    )
    .map_err(|_| XHCIError::MemoryAllocationFailure)?;

    mmio::map_page_as_uncacheable(
        PhysAddr::new(full_bar + (capablities.doorbell_offset as u64)),
        mapper,
    )
    .map_err(|_| XHCIError::MemoryAllocationFailure)?;

    let primary_event_ring =
        create_device_event_ring_no_info(base_virtual_address, capablities, mapper, 0).unwrap();

    Result::Ok(XHCIInfo {
        base_address: base_virtual_address,
        capablities,
        operational_register_address: operational_start,
        base_address_array: virtual_adddr,
        command_ring: Arc::new(Mutex::new(command_ring)),
        primary_event_ring: Arc::new(Mutex::new(primary_event_ring)),
    })
}

fn boot_up_all_ports(
    info: &mut XHCIInfo,
    mapper: &mut OffsetPageTable,
) -> Result<Vec<USBDeviceInfo>, XHCIError> {
    let mut devices = Vec::new();
    for device in 0..MAX_USB_DEVICES {
        let device_offset: u64 = 0x10 * <u8 as Into<u64>>::into(device);
        let port_status_addr =
            (info.operational_register_address + 0x400 + device_offset) as *const u32;
        let device_connected = unsafe {
            PortStatusAndControl::from_bits_retain(core::ptr::read_volatile(port_status_addr))
        };
        if PortStatusAndControl::CurrentConnectStatus.intersects(device_connected) {
            let slot = boot_up_usb_port(info, device, device_connected, mapper)?;
            let address_tuple = address_device(info, slot, mapper)?;
            let input_context = address_tuple.0;
            let producer_buffer = address_tuple.1;
            // Issue the get_descriptor

            let event_ring = create_device_event_ring(info, slot as u16, mapper)?;
            let device = prepare_device(event_ring, producer_buffer, slot, input_context)?;
            devices.push(device);
        } else {
            continue;
        }
    }

    Result::Ok(devices)
}

/// Sets up the device in a struct to be passed to class drivers
fn prepare_device(
    event_ring: ConsumerRingBuffer,
    producer_ring_buffer: ProducerRingBuffer,
    slot: u8,
    input_context_vaddr: VirtAddr,
) -> Result<USBDeviceInfo, XHCIError> {
    let device_descriptor: MaybeUninit<USBDeviceDescriptor> = MaybeUninit::zeroed();
    let device_descriptor = unsafe { device_descriptor.assume_init() };
    Result::Ok(USBDeviceInfo {
        descriptor: device_descriptor,
        command_ring: producer_ring_buffer,
        event_ring,
        input_context_vaddr,
        slot,
    })
}

fn boot_up_usb_port(
    info: &mut XHCIInfo,
    device: u8,
    port_status: PortStatusAndControl,
    mapper: &OffsetPageTable,
) -> Result<u8, XHCIError> {
    let port_link_status = (port_status.bits() >> 5) & 0b1111;
    if PortStatusAndControl::PortEnabled.intersects(port_status) {
        debug_println!("USB3 detected and successfull");
    } else if port_link_status == PortLinkStateRead::Polling as u32 {
        let mut new_status = port_status.union(PortStatusAndControl::PortReset);
        new_status.remove(PortStatusAndControl::CurrentConnectStatus);
        new_status = PortStatusAndControl::from_bits_retain(new_status.bits() & (!(0b1111 << 5)));
        let device_offset: u64 = 0x10 * <u8 as Into<u64>>::into(device);
        let port_status_addr =
            (info.operational_register_address + 0x400 + device_offset) as *mut u32;
        unsafe {
            core::ptr::write_volatile(port_status_addr, new_status.bits());
        }
    } else if port_link_status == PortLinkStateRead::RxDetect as u32 {
        debug_println!("USB3 detected and failed");
    } else {
        return Result::Err(XHCIError::UnknownPort);
    }
    let event_ring_lock = info.primary_event_ring.clone();
    let mut primary_event_ring = event_ring_lock.lock();
    let mut event_result = unsafe { primary_event_ring.dequeue() };
    while event_result.is_err() {
        event_result = unsafe { primary_event_ring.dequeue() };
        core::hint::spin_loop();
    }
    let _event = event_result.map_err(|_| XHCIError::Timeout)?;
    // Now Enable the slot (4.3.2)
    let mut block = TransferRequestBlock {
        parameters: 0,
        status: 0,
        control: 0,
    };
    block.set_trb_type(TrbTypes::EnableSlotCmd as u32);
    let command_ring_lock = info.command_ring.clone();
    let mut command_ring = command_ring_lock.lock();
    unsafe {
        command_ring
            .enqueue(block)
            .map_err(|_| XHCIError::CommandRingError)?
    };

    let doorbell_base: *mut u32 =
        (info.base_address.as_u64() + info.capablities.doorbell_offset as u64) as *mut u32;
    unsafe { core::ptr::write_volatile(doorbell_base, 0) };
    drop(command_ring);
    drop(primary_event_ring);
    // Now wait for response
    let event = wait_for_events_including_command_completion(info, mapper)?;
    let slot: u8 = (event.control >> 24).try_into().expect("Masked out bits");
    Result::Ok(slot)
}

/// The first virtual address is for the device_context, while the second is for the producer
/// ring buffer
fn address_device(
    info: &mut XHCIInfo,
    slot: u8,
    mapper: &mut OffsetPageTable,
) -> Result<(VirtAddr, ProducerRingBuffer), XHCIError> {
    // We need 2 pages, one for the device context, and the other for ring buffer(s)
    // Start by setting up ring buffers

    let buffer_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let buffer_address = map_page_as_uncacheable(buffer_frame.start_address(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    zero_out_page(Page::containing_address(buffer_address));
    let producer_ring_buffer = ProducerRingBuffer::new(
        buffer_frame.start_address(),
        1,
        RingType::Transfer,
        (PAGE_SIZE).try_into().unwrap(),
        mapper.phys_offset(),
    )
    .expect("Everything should be alligned");

    // For device context see Figure 4-1 of xhci spec (Page 95)
    let device_context_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let mut device_context_address =
        map_page_as_uncacheable(device_context_frame.start_address(), mapper)
            .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    device_context_address += 0x20;
    mmio::zero_out_page(Page::containing_address(device_context_address));

    // Start with the input control context (ICC in this code)
    let input_control_context_ptr: *mut InputControlContext = device_context_address.as_mut_ptr();
    let mut icc = unsafe { *input_control_context_ptr };
    icc.set_add_flag(0, 1);
    icc.set_add_flag(1, 1);
    unsafe { core::ptr::write_volatile(input_control_context_ptr, icc) };

    // Now handle slot context
    // TODO: Fix as it assumes 32 byte slot context
    let slot_context_va = device_context_address + 0x20;
    let slot_context_ptr: *mut SlotContext = slot_context_va.as_mut_ptr();
    let mut slot_context = unsafe { core::ptr::read_volatile(slot_context_ptr) };
    slot_context.set_root_hub_port(slot.into());
    slot_context.set_context_entries(1);
    slot_context.set_route_string(0);
    unsafe {
        core::ptr::write_volatile(slot_context_ptr, slot_context);
    }

    // Endpoint 0 context (Bidirectional)
    let ep0_context_va = device_context_address + 0x40;
    let ep0_context_ptr: *mut EndpointContext = ep0_context_va.as_mut_ptr();
    let mut endpoint_zero_context = unsafe { *ep0_context_ptr };

    endpoint_zero_context.set_eptype(4);
    // TODO: fix max packet size to not be hard coded
    endpoint_zero_context.set_max_packet_size(8);
    endpoint_zero_context.set_max_burst_size(0);
    endpoint_zero_context.set_dcs(1);
    endpoint_zero_context.set_interval(0);
    endpoint_zero_context.set_maxpstreams(0);
    endpoint_zero_context.set_mult(0);
    endpoint_zero_context.set_cerr(3);
    endpoint_zero_context.set_trdequeue_ptr(buffer_address - mapper.phys_offset());
    unsafe {
        core::ptr::write_volatile(ep0_context_ptr, endpoint_zero_context);
    }
    // Load output to device context base array
    let slot_addr_vadr = info.base_address_array + (slot as u64 * 8);
    let slot_addr = slot_addr_vadr.as_mut_ptr();
    unsafe {
        core::ptr::write_volatile(slot_addr, slot_context_va - mapper.phys_offset());
    }

    // Address the device
    let big_device: u32 = slot.into();
    let block = TransferRequestBlock {
        parameters: (device_context_address - mapper.phys_offset()),
        status: 0,
        control: ((big_device << 24) | ((TrbTypes::AddressDeviceCmd as u32) << 10)),
    };
    let command_ring_lock = info.command_ring.clone();
    let mut command_ring = command_ring_lock.lock();
    unsafe {
        command_ring
            .enqueue(block)
            .map_err(|_| XHCIError::CommandRingError)?
    };
    let doorbell_base: *mut u32 =
        (info.base_address.as_u64() + info.capablities.doorbell_offset as u64) as *mut u32;
    unsafe { core::ptr::write_volatile(doorbell_base, 0) };
    drop(command_ring);
    wait_for_events_including_command_completion(info, mapper)?;

    Result::Ok((device_context_address, producer_ring_buffer))
}

/// Sets up an event ring for the specific interrupter
fn create_device_event_ring(
    info: &XHCIInfo,
    interrupter: u16,
    mapper: &mut OffsetPageTable,
) -> Result<ConsumerRingBuffer, XHCIError> {
    create_device_event_ring_no_info(
        VirtAddr::new(info.base_address.as_u64()),
        info.capablities,
        mapper,
        interrupter,
    )
}

fn create_device_event_ring_no_info(
    base_address: VirtAddr,
    capablities: XHCICapabilities,
    mapper: &mut OffsetPageTable,
    interrupter: u16,
) -> Result<ConsumerRingBuffer, XHCIError> {
    assert!(interrupter < 1024);

    // Allocate space for the primary event ring
    let erst_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let erst_vaddr = mmio::map_page_as_uncacheable(erst_frame.start_address(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    let er_segment_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let er_segment_vaddr = mmio::map_page_as_uncacheable(er_segment_frame.start_address(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;

    // zero out pages
    let erst_page: Page = Page::containing_address(erst_vaddr);
    let ers_page: Page = Page::containing_address(er_segment_vaddr);
    mmio::zero_out_page(erst_page);
    mmio::zero_out_page(ers_page);

    // get the max size of erst
    let erst_max = (capablities.structural_paramaters_2 >> 4) & 0xF;
    let max_size: isize = 1 << erst_max;

    // try to create the ring. this initializes the segments to zero and the erst
    let event_ring = ConsumerRingBuffer::new(
        erst_page.start_address().as_u64(),
        max_size,
        ers_page.start_address(),
        er_segment_frame.start_address(),
        4096 / 16,
    )
    .expect("Error initializing consumer ring.");

    // write the necessary data to the event ring fields of the specifified interrupter register
    let erstsz_addr = (base_address.as_u64()
        + (capablities.runtime_register_space_offset as u64)
        + ((interrupter as u64) * 32)
        + 0x28) as *mut u32;
    let erst_size: u32 = 1 & 0xFFFF;
    let erstba_addr = (base_address.as_u64()
        + (capablities.runtime_register_space_offset as u64)
        + ((interrupter as u64) * 32)
        + 0x30) as *mut u64;
    let erst_ba = erst_frame.start_address().as_u64();
    let erdp_addr = (base_address.as_u64()
        + (capablities.runtime_register_space_offset as u64)
        + ((interrupter as u64) * 32)
        + 0x38) as *mut u64;
    unsafe {
        // write the number of entries in the erst to the erst size register
        core::ptr::write_volatile(erstsz_addr, erst_size);
        // write the base address of the erst to the event ring dequeue pointer register
        core::ptr::write_volatile(erdp_addr, er_segment_frame.start_address().as_u64());
        // write the base address of the erst to the erst base address register
        core::ptr::write_volatile(erstba_addr, erst_ba);
    }
    Result::Ok(event_ring)
}

/// Wait for an event to occur in the event ring. This should not be a
/// command completion event.
fn wait_for_events(
    info: &XHCIInfo,
    event_ring: &mut ConsumerRingBuffer,
    interrupter: u16,
    mapper: &OffsetPageTable,
) -> Result<TransferRequestBlock, XHCIError> {
    // TODO: make this async
    let mut event_result = unsafe { event_ring.dequeue() };
    while event_result.is_err() {
        event_result = unsafe { event_ring.dequeue() };
        core::hint::spin_loop();
    }
    let event = event_result.map_err(|_| XHCIError::Timeout)?;

    // if this is a command completion event, update the command ring's dequeue ptr
    let trb_type = event.get_trb_type();
    assert!(
        trb_type != TrbTypes::CmdCompleteEvent as u32,
        "Use wait_for_events_including command completion if there is a command completion event"
    );
    let erdp_addr = info.base_address
        + info.capablities.runtime_register_space_offset as u64
        + 0x38
        + (32 * interrupter as u64);
    unsafe {
        update_deque_ptr(erdp_addr.as_mut_ptr(), event_ring, mapper);
    }
    Result::Ok(event)
}

fn wait_for_events_including_command_completion(
    info: &mut XHCIInfo,
    mapper: &OffsetPageTable,
) -> Result<TransferRequestBlock, XHCIError> {
    // TODO: make this async
    let event_ring_lock = info.primary_event_ring.clone();
    let mut event_ring = event_ring_lock.lock();
    let mut event_result = unsafe { event_ring.dequeue() };
    drop(event_ring);
    while event_result.is_err() {
        let mut event_ring = event_ring_lock.lock();
        event_result = unsafe { event_ring.dequeue() };
        core::hint::spin_loop();
        drop(event_ring);
    }
    let event = event_result.map_err(|_| XHCIError::Timeout)?;

    // if this is a command completion event, update the command ring's dequeue ptr
    let trb_type = event.get_trb_type();
    if trb_type == TrbTypes::CmdCompleteEvent as u32 {
        // TODO: figure out the completion codes where the parameter field is not valid
        let command_ptr = event.parameters;
        let new_dequeue: u64 = command_ptr + mapper.phys_offset().as_u64();
        let command_ring_lock = info.command_ring.clone();
        let mut command_ring = command_ring_lock.lock();
        command_ring
            .set_dequeue(new_dequeue)
            .expect("address was unaligned");
    }

    let erdp_addr =
        info.base_address + info.capablities.runtime_register_space_offset as u64 + 0x38;
    let event_ring_lock = info.primary_event_ring.clone();
    let event_ring = event_ring_lock.lock();
    unsafe {
        update_deque_ptr(erdp_addr.as_mut_ptr(), &event_ring, mapper);
    }
    Result::Ok(event)
}

/// Updates the dequeue pointer in dequeue pointer register to match the event ring
///
/// # Safety
///
/// deque_pointer_register should be mapped as uncachable memory and
/// be the actual virtual address of the deque pointer
pub unsafe fn update_deque_ptr(
    deque_pointer_register: *mut u64,
    event_ring: &ConsumerRingBuffer,
    mapper: &OffsetPageTable,
) {
    let deque = event_ring.get_dequeue();
    // Now we need the physical addr of the deque ptr, so we grab mapper
    let result = mapper.translate(VirtAddr::new(deque));
    match result {
        TranslateResult::Mapped {
            frame,
            offset,
            flags: _,
        } => {
            let deque_physical = frame.start_address() + offset;
            unsafe { core::ptr::write_volatile(deque_pointer_register, deque_physical.as_u64()) };
        }
        TranslateResult::InvalidFrameAddress(_) => {
            panic!("dequeue pointer should always point to valid memory")
        }
        TranslateResult::NotMapped => {
            panic!("dequeue pointer should always point to valid memory")
        }
    }
}
