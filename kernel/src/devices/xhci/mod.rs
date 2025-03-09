//! Deals with the XHCI controller and XHCI root hub ports
//!
//! XHCI Spec refers to Revision 1.2 found here
//! https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf

pub mod context;
pub mod ring_buffer;

use core::cmp::min;

use crate::{constants::memory::PAGE_SIZE, debug_println, memory::frame_allocator::alloc_frame};
use alloc::{sync::Arc, vec::Vec};
use bitflags::bitflags;
use ring_buffer::{ConsumerRingBuffer, ProducerRingBuffer, TransferRequestBlock, TrbTypes};
use spin::Mutex;
use x86_64::{
    structures::paging::{OffsetPageTable, Page},
    PhysAddr,
};

use super::{
    mmio::{self, map_page_as_uncacheable},
    pci::{read_config, DeviceInfo},
};

const MAX_USB_DEVICES: u8 = 8;

/// See section 5.3 of the xHCI spec
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
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
#[allow(dead_code)]
struct XHCIInfo {
    base_address: u64,
    capablities: XHCICapabilities,
    operational_register_address: u64,
    base_address_array: u64,
    command_ring_base: u64,
    command_ring: ProducerRingBuffer,
    primary_event_ring: ConsumerRingBuffer,
}

#[derive(Debug)]
pub enum XHCIError {
    MemoryAllocationFailure,
    NoFrameAllocator,
    UnknownPort,
    CommandRingError,
    Timeout,
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
enum PortLinkStateRead {
    U0 = 0,
    U1 = 1,
    U2 = 2,
    /// U3 =  Device Suspended
    U3 = 3,
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
pub fn initalize_xhci_hub(
    device: &Arc<Mutex<DeviceInfo>>,
    mapper: &mut OffsetPageTable,
) -> Result<(), XHCIError> {
    let device_lock = device.clone();
    let xhci_device = device_lock.lock();
    let bar_0: u64 =
        (read_config(xhci_device.bus, xhci_device.device, 0, 0x10) & 0xFFFFFFF0).into();
    let bar_1: u64 = read_config(xhci_device.bus, xhci_device.device, 0, 0x14).into();
    debug_println!("Bar 0 = 0x{bar_0} Bar 1 = 0x{bar_1}");
    let full_bar = (bar_1 << 32) | bar_0;

    debug_println!("Full bar = 0x{full_bar:X}");

    let mut info = initalize_xhciinfo(full_bar, mapper)?;
    // Turn on device
    run_host_controller(&info);
    boot_up_all_ports(&mut info, mapper)?;
    Result::Ok(())
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

/// Runs a software reset of the xchi controller
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

fn initalize_xhciinfo(full_bar: u64, mapper: &mut OffsetPageTable) -> Result<XHCIInfo, XHCIError> {
    let base_virtual_address =
        mmio::map_page_as_uncacheable(PhysAddr::new(full_bar), mapper).unwrap();
    let address = base_virtual_address.as_u64();
    let capablities = get_host_controller_cap_regs(address);
    let extended_reg_length: u64 = capablities.register_length.into();
    let operational_start = address + extended_reg_length;
    reset_xchi_controller(operational_start);

    // Program max device device slots
    let config_reg_addr = (operational_start + 0x38) as *mut u32;
    // Extract the max device slots from the capability parameters 1 register
    let mut max_devices: u32 = capablities.capability_paramaters_1 & 0xFF;
    max_devices = min(max_devices, MAX_USB_DEVICES.into());
    unsafe { core::ptr::write_volatile(config_reg_addr, max_devices) }
    // Allocate space for DCBAAP (Device Context Base Array Pointer Register)
    // let mut allocator_tmp = FRAME_ALLOCATOR.lock();
    // let allocator = allocator_tmp.as_mut().ok_or(XHCIError::NoFrameAllocator)?;
    // let frame = allocator
    //     .allocate_frame()
    //     .ok_or(XHCIError::MemoryAllocationFailure)?;
    let dcbaap_frame = alloc_frame().expect("Frame allocation failed");
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
    let cmd_frame = alloc_frame().expect("Frame allocation failed");
    // let cmd_frame = allocator
    //     .allocate_frame()
    //     .ok_or(XHCIError::MemoryAllocationFailure)?;
    let cmd_vaddr = mmio::map_page_as_uncacheable(cmd_frame.start_address(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;

    // We need to zero out this page as well
    let cmd_page: Page = Page::containing_address(cmd_vaddr);
    mmio::zero_out_page(cmd_page);

    // set Command Ring Control reg to starting addr of command ring.
    let crcreg_addr = (operational_start + 0x18) as *mut u64;
    let crcreg_value = cmd_frame.start_address().as_u64() | 1;
    debug_println!("cmd ring base: {:X}", crcreg_value);
    unsafe {
        core::ptr::write_volatile(crcreg_addr, crcreg_value);
    }

    // create the command ring data structure.
    let command_ring = ProducerRingBuffer::new(
        cmd_page.start_address().as_u64(),
        1,
        ring_buffer::RingType::Command,
        PAGE_SIZE.try_into().unwrap(),
    )
    .expect("error initializing command_ring");

    // Allocate space for the primary event ring
    let erst_frame = alloc_frame().expect("Frame allocation failed");
    // let erst_frame = allocator
    //     .allocate_frame()
    //     .ok_or(XHCIError::MemoryAllocationFailure)?;
    let erst_vaddr = mmio::map_page_as_uncacheable(erst_frame.start_address(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    let er_segment_frame = alloc_frame().expect("Frame allocation failed");
    debug_println!(
        "ers frame addr: {:X}",
        er_segment_frame.start_address().as_u64()
    );
    // let er_segment_frame = allocator
    //     .allocate_frame()
    //     .ok_or(XHCIError::MemoryAllocationFailure)?;
    debug_println!("before er seg mao");
    let er_segment_vaddr = mmio::map_page_as_uncacheable(er_segment_frame.start_address(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;
    debug_println!("ers vaddr: {:X}", er_segment_vaddr);

    // drop allocator lock
    // drop(allocator_tmp);

    // zero out pages
    let erst_page: Page = Page::containing_address(erst_vaddr);
    let ers_page: Page = Page::containing_address(er_segment_vaddr);
    mmio::zero_out_page(erst_page);
    mmio::zero_out_page(ers_page);

    // get the max size of erst
    let erst_max = (capablities.structural_paramaters_2 >> 4) & 0xF;
    let max_size: isize = 1 << erst_max;

    // try to create the ring. this initializes the segments to zero and the erst
    let primary_event_ring = ConsumerRingBuffer::new(
        erst_page.start_address().as_u64(),
        max_size,
        ers_page.start_address(),
        er_segment_frame.start_address(),
        4096 / 16,
    )
    .expect("error initializing primary event ring");
    unsafe {
        let mut addr = erst_vaddr.as_u64() as *const u64;
        let base_address = core::ptr::read_volatile(addr);
        debug_println!("Base address = 0x{base_address:X}");
        debug_println!(
            "Base addr should be 0x{:X}",
            er_segment_frame.start_address().as_u64()
        );

        addr = (erst_vaddr.as_u64() + 0x8) as *const u64;
        let size = core::ptr::read_volatile(addr);
        debug_println!("Size = {size}");
    }
    unsafe {
        primary_event_ring.print_ring();
    }

    mmio::map_page_as_uncacheable(
        PhysAddr::new(full_bar + (capablities.runtime_register_space_offset as u64)),
        mapper,
    )
    .map_err(|_| XHCIError::MemoryAllocationFailure)
    .unwrap();

    mmio::map_page_as_uncacheable(
        PhysAddr::new(full_bar + (capablities.doorbell_offset as u64)),
        mapper,
    )
    .map_err(|_| XHCIError::MemoryAllocationFailure)
    .unwrap();
    // write the necessary data to the event ring fields of the 0th interrupter register
    let erstsz_addr =
        (address + (capablities.runtime_register_space_offset as u64) + 0x28) as *mut u32;
    let erst_size: u32 = 1 & 0xFFFF;
    let erstba_addr =
        (address + (capablities.runtime_register_space_offset as u64) + 0x30) as *mut u64;
    let erst_ba = erst_frame.start_address().as_u64();
    debug_println!("event ring base address: {:X}", erst_ba);
    let erdp_addr =
        (address + (capablities.runtime_register_space_offset as u64) + 0x38) as *mut u64;
    unsafe {
        // write the number of entries in the erst to the erst size register
        core::ptr::write_volatile(erstsz_addr, erst_size);
        // write the base address of the erst to the event ring dequeue pointer register
        core::ptr::write_volatile(erdp_addr, er_segment_frame.start_address().as_u64());
        // write the base address of the erst to the erst base address register
        core::ptr::write_volatile(erstba_addr, erst_ba);
        let erstsz_value = core::ptr::read_volatile(erstsz_addr);
        let erstba_value = core::ptr::read_volatile(erstba_addr);
        let erdp_value = core::ptr::read_volatile(erdp_addr);
        debug_println!("erstsz value: {}", erstsz_value);
        debug_println!("erstba value: {:X}", erstba_value);
        debug_println!("erdp value: {:X}", erdp_value);
    }

    Result::Ok(XHCIInfo {
        base_address: address,
        capablities,
        operational_register_address: operational_start,
        base_address_array: dcbaap_frame.start_address().as_u64(),
        command_ring_base: cmd_frame.start_address().as_u64(),
        command_ring,
        primary_event_ring,
    })
}

fn boot_up_all_ports(info: &mut XHCIInfo, mapper: &mut OffsetPageTable) -> Result<(), XHCIError> {
    for device in 0..MAX_USB_DEVICES {
        debug_println!("Device = {device}");
        let device_offset: u64 = 0x10 * <u8 as Into<u64>>::into(device);
        let port_status_addr =
            (info.operational_register_address + 0x400 + device_offset) as *const u32;
        // debug_println!("Offset = {port_status_addr:?}, device = {device}");
        let device_connected = unsafe {
            PortStatusAndControl::from_bits_retain(core::ptr::read_volatile(port_status_addr))
        };
        // debug_println!("PortStatusAndCtrl = {device_connected:?}");
        if PortStatusAndControl::CurrentConnectStatus.intersects(device_connected) {
            debug_println!("PortStatusAndCtrl = {device_connected:?}");
            boot_up_usb_port(info, device, device_connected)?;
            setup_input_context(info, device, mapper)?;
        } else {
            continue;
        }
    }

    Result::Ok(())
}

fn boot_up_usb_port(
    info: &mut XHCIInfo,
    device: u8,
    port_status: PortStatusAndControl,
) -> Result<(), XHCIError> {
    let port_link_status = (port_status.bits() >> 5) & 0b1111;
    if PortStatusAndControl::PortEnabled.intersects(port_status) {
        debug_println!("USB3 detected and successfull");
    } else if port_link_status == PortLinkStateRead::Polling as u32 {
        debug_println!("USB2 detected, or USB3 still working");
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

    let mut event_result = unsafe { info.primary_event_ring.dequeue() };
    while event_result.is_err() {
        event_result = unsafe { info.primary_event_ring.dequeue() };
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
    unsafe {
        info.command_ring
            .enqueue(block)
            .map_err(|_| XHCIError::CommandRingError)?
    };

    let doorbell_base: *mut u32 =
        (info.base_address + info.capablities.doorbell_offset as u64) as *mut u32;
    unsafe { core::ptr::write_volatile(doorbell_base, 0) };

    // Now wait for response

    let mut event_result = unsafe { info.primary_event_ring.dequeue() };
    while event_result.is_err() {
        event_result = unsafe { info.primary_event_ring.dequeue() };
        core::hint::spin_loop();
    }
    let event = event_result.map_err(|_| XHCIError::Timeout)?;
    unsafe { info.primary_event_ring.is_empty() };
    debug_println!("Type = {}", event.get_trb_type());
    debug_println!("Is empty = {}", unsafe {
        info.primary_event_ring.is_empty()
    });
    debug_println!("Test");
    Result::Ok(())
}

fn setup_input_context(
    _info: &mut XHCIInfo,
    _device: u8,
    mapper: &mut OffsetPageTable,
) -> Result<(), XHCIError> {
    let input_frame = alloc_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    let _input_frame_vaddr = map_page_as_uncacheable(input_frame.start_address(), mapper);
    Result::Ok(())
}

#[cfg(test)]
mod test {
    use x86_64::structures::paging::Mapper;

    use super::{
        ring_buffer::{ProducerRingBuffer, RingType, Trb, TrbTypes},
        *,
    };
    use crate::{
        devices::xhci::ring_buffer::{ConsumerRingBuffer, ProducerRingError, TransferRequestBlock},
        memory::{
            paging::{create_mapping, remove_mapped_frame},
            MAPPER,
        },
    };

    #[test_case]
    fn prod_ring_buffer_init() {
        // first get a page and zero init it
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // call the new function
        let base_addr = page.start_address().as_u64();
        let size = page.size() as isize;
        let _cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size)
            .expect("Intialization failed");

        // make sure the link trb is set correctly
        let mut trb_ptr = base_addr as *const Trb;
        let trb: Trb;
        unsafe {
            trb_ptr = trb_ptr.offset(size / 16 - 1);
            trb = *trb_ptr;
        }

        let params = trb.parameters;
        let status = trb.status;
        let control = trb.control;

        assert_eq!(params, base_addr);
        assert_eq!(status, 0);
        assert_eq!(control, 0x1802);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn prod_ring_buffer_enqueue() {
        // initialize a ring buffer we can enqueue onto
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // call the new function
        let base_addr = page.start_address().as_u64();
        let size = page.size() as isize;
        let mut cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size)
            .expect("Intialization failed");

        // create a block to queue
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_trb_type(TrbTypes::NoOpCmd as u32);

        // enqueue the block
        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        let ring_base = base_addr as *mut Trb;
        let mut trb: Trb;
        unsafe {
            trb = *ring_base;
        }
        assert_eq!(trb.get_trb_type(), TrbTypes::NoOpCmd as u32);
        assert_eq!(trb.get_cycle(), 1);

        // enqueue another block
        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
            trb = *(ring_base.offset(1));
        }
        assert_eq!(trb.get_trb_type(), TrbTypes::NoOpCmd as u32);
        assert_eq!(trb.get_cycle(), 1);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn prod_ring_buffer_helpers() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // create a small ring buffer
        let base_addr = page.start_address().as_u64();
        let size: isize = 64;
        let mut cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size)
            .expect("Intialization failed");

        // test is empty and is full funcs
        let mut result = cmd_ring.is_ring_empty();
        assert_eq!(result, true);

        unsafe {
            result = cmd_ring.is_ring_full();
        }

        assert_eq!(result, false);

        // create a no-op cmd to queue a couple of times
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_trb_type(TrbTypes::NoOpCmd as u32);

        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        // both empty and true should be false
        result = cmd_ring.is_ring_empty();
        assert_eq!(result, false);

        unsafe {
            result = cmd_ring.is_ring_full();
            assert_eq!(result, false);
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        // empty should be false and full should be true
        result = cmd_ring.is_ring_empty();
        assert_eq!(result, false);

        unsafe {
            result = cmd_ring.is_ring_full();
        }
        assert_eq!(result, true);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn prod_ring_buffer_errors() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // First test the new function with unaligned address
        let mut base_addr = page.start_address().as_u64();
        base_addr += 1;
        let mut size: isize = 64;
        let mut result =
            ProducerRingBuffer::new(base_addr, 1, RingType::Command, size).unwrap_err();

        assert_eq!(result, ProducerRingError::UnalignedAddress);

        // now test with unaligned size
        base_addr -= 1;
        size += 5;
        result = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size).unwrap_err();

        assert_eq!(result, ProducerRingError::UnalignedSize);
        size -= 5;

        // make an actual proper cmd ring
        let mut cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size)
            .expect("Intialization failed");

        // now begin testing the setters for unaligned address
        result = cmd_ring.set_enqueue(base_addr + 18).unwrap_err();
        assert_eq!(result, ProducerRingError::UnalignedAddress);

        result = cmd_ring.set_dequeue(base_addr + 18).unwrap_err();
        assert_eq!(result, ProducerRingError::UnalignedAddress);

        // try to enqueue a transfer type TRB
        let mut transfer_trb = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        transfer_trb.set_trb_type(TrbTypes::SetupStage as u32);
        unsafe {
            result = cmd_ring.enqueue(transfer_trb).unwrap_err();
        }
        assert_eq!(result, ProducerRingError::InvalidType);

        // test enqueue buffer full error
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_trb_type(TrbTypes::NoOpCmd as u32);

        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
            cmd_ring.enqueue(cmd).expect("enqueue error");
            result = cmd_ring.enqueue(cmd).unwrap_err();
        }
        assert_eq!(result, ProducerRingError::BufferFullError);

        // create a transfer ring so we can test the invalid type error on it
        let mut transfer_ring =
            ProducerRingBuffer::new(base_addr, 1, RingType::Transfer, size).expect("init failed");

        // test enqueue invalid type err
        unsafe {
            result = transfer_ring.enqueue(cmd).unwrap_err();
        }
        assert_eq!(result, ProducerRingError::InvalidType);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn prod_ring_buffer_enqueue_accross_segment() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // create a small ring buffer
        let base_addr = page.start_address().as_u64();
        let size: isize = 64;
        let mut cmd_ring = ProducerRingBuffer::new(base_addr, 1, RingType::Command, size)
            .expect("Intialization failed");

        // create our no op cmd
        let mut cmd = Trb {
            parameters: 0,
            status: 0,
            control: 0,
        };
        cmd.set_trb_type(TrbTypes::NoOpCmd as u32);

        // queue it up so we can test that later the cycle bit gets correctly written
        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }
        // move the enqueue to the last block before the end and then the dequeue over one
        cmd_ring
            .set_enqueue(base_addr + 32)
            .expect("unaligned address");
        cmd_ring
            .set_dequeue(base_addr + 16)
            .expect("unaligned address");

        // now try to enqueue
        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        // ring should be considered full now
        unsafe {
            assert!(cmd_ring.is_ring_full());
        }

        // now move dequeue so we can test that enqueue properly writes the cycle bit to 0
        cmd_ring
            .set_dequeue(base_addr + 32)
            .expect("unaligned address");

        unsafe {
            cmd_ring.enqueue(cmd).expect("enqueue error");
        }

        // now lettuce check that the cycle bit of the very first block is 0
        let trb_ptr = base_addr as *const Trb;
        let trb: Trb;
        unsafe {
            trb = *trb_ptr;
        }

        assert_eq!(trb.get_cycle(), 0);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn consumer_ring_buffer_init() {
        // first get pages for the ERST and first segment
        let mut mapper: spin::MutexGuard<'_, OffsetPageTable<'_>> = MAPPER.lock();
        let erst_page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let segment_page: Page = Page::containing_address(VirtAddr::new(0x600000000));
        let _ = create_mapping(erst_page, &mut *mapper, None);
        let _ = create_mapping(segment_page, &mut *mapper, None);
        let segment_frame = mapper
            .translate_page(segment_page)
            .expect("error translating page");
        let segment_frame_addr = segment_frame.start_address();

        let erst_entry_size = 16 as isize;

        mmio::zero_out_page(erst_page);
        mmio::zero_out_page(segment_page);

        // call the initialization function
        let erst_address = erst_page.start_address().as_u64();
        let segment_address = segment_page.start_address().as_u64();
        let page_size = erst_page.size() as isize;
        let _event_ring = ConsumerRingBuffer::new(
            erst_address,
            page_size / erst_entry_size,
            segment_address,
            segment_frame_addr,
            (page_size / size_of::<TransferRequestBlock>() as isize) as u32,
        )
        .expect("error initializing event ring");

        // verify that the ERST was properly initialized

        // check that the first TRB's worth of the ERST contains the correct information about the segment
        let mut trb_ptr = erst_address as *const Trb;
        let mut trb;
        unsafe {
            trb = *trb_ptr;
        }

        // added due to "unaligned padded struct field" error, probably not actually a good solution, I'd like
        // to know how we were unaligned
        let mut parameters = trb.parameters;
        let mut status = trb.status;
        let mut control = trb.control;

        assert_eq!(parameters, segment_address);
        assert_eq!(
            status,
            (page_size / size_of::<TransferRequestBlock>() as isize) as u32
        );
        assert_eq!(control, 0);

        // check that the rest of the TRB's worth of the ERST is still zeroed
        for index in 1..(page_size / erst_entry_size) {
            unsafe {
                trb_ptr = trb_ptr.offset(1);
                trb = *trb_ptr;
            }

            parameters = trb.parameters;
            status = trb.status;
            control = trb.control;

            assert_eq!(parameters, 0);
            assert_eq!(status, 0);
            assert_eq!(control, 0);
        }

        // check that the data segment remains untouched
        trb_ptr = segment_address as *const Trb;
        unsafe {
            trb = *trb_ptr;
        }

        for index in 1..(page_size / erst_entry_size) {
            parameters = trb.parameters;
            status = trb.status;
            control = trb.control;

            assert_eq!(parameters, 0);
            assert_eq!(status, 0);
            assert_eq!(control, 0);

            unsafe {
                assert_eq!(size_of::<TransferRequestBlock>() as isize, 16);
                trb_ptr = trb_ptr.offset(1);
                trb = *trb_ptr;
            }
        }

        remove_mapped_frame(erst_page, &mut *mapper);
        remove_mapped_frame(segment_page, &mut *mapper);
    }
}
