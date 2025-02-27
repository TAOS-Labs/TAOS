pub mod context;
pub mod transfer_ring_block;

use core::cmp::min;

use alloc::{sync::Arc, vec::Vec};
use bitflags::bitflags;
use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, OffsetPageTable};

use crate::{debug_println, memory::frame_allocator::FRAME_ALLOCATOR};

use super::{
    mmio,
    pci::{read_config, DeviceInfo},
};

const MAX_USB_DEVICES: u8 = 4;
const MAX_USB_DEVICES_SIZE: usize = 4;

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
    base_address_array: [u64; MAX_USB_DEVICES_SIZE],
}

#[derive(Debug)]
pub enum XHCIError {
    MemoryAllocationFailure,
    NoFrameAllocator,
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
pub fn initalize_xhci_hub(device: &Arc<Mutex<DeviceInfo>>, mapper: &mut OffsetPageTable)  -> Result<(), XHCIError>{
    let device_lock = device.clone();
    let xhci_device = device_lock.lock();
    let bar_0: u64 =
        (read_config(xhci_device.bus, xhci_device.device, 0, 0x10) & 0xFFFFFFF0).into();
    let bar_1: u64 = read_config(xhci_device.bus, xhci_device.device, 0, 0x14).into();
    debug_println!("Bar 0 = 0x{bar_0} Bar 1 = 0x{bar_1}");
    let full_bar = (bar_1 << 32) | bar_0;

    debug_println!("Full bar = 0x{full_bar:X}");
    let address = mmio::map_page_as_uncacheable(full_bar, mapper).unwrap();
    let capablities = get_host_controller_cap_regs(address);
    let extended_reg_length: u64 = capablities.register_length.into();
    let operational_start = address + extended_reg_length;
    reset_xchi_controller(operational_start);
    let base_address_array: [u64; MAX_USB_DEVICES_SIZE] = [0; MAX_USB_DEVICES_SIZE];
    let info = XHCIInfo {
        base_address: address,
        capablities,
        operational_register_address: operational_start,
        base_address_array,
    };
    initalize_reset_xhci_controller(&info)?;
    debug_println!("0x{address:X} {capablities:?}");
    Result::Ok(())
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

fn initalize_reset_xhci_controller(info: &XHCIInfo) -> Result<(), XHCIError> {
    // Program max device device slots
    let config_reg_addr = (info.operational_register_address + 0x38) as *mut u32;
    // Extract the max device slots from the capability parameters 1 register
    let mut max_devices: u32 = info.capablities.capability_paramaters_1 & 0xFF;
    max_devices = min(max_devices, MAX_USB_DEVICES.into());
    unsafe { core::ptr::write_volatile(config_reg_addr, max_devices) }
    // Allocate space for DCBAAP (Device Context Base Array Pointer Register)
    let mut allator_tmp = FRAME_ALLOCATOR.lock();
    let allocator = allator_tmp.as_mut().ok_or(XHCIError::NoFrameAllocator)?;
    let frame = allocator.allocate_frame().ok_or(XHCIError::MemoryAllocationFailure)?;
    // We need to zero out shit
    // TODO!
    // set DCBAAP (Device Context Base Array Pointer Register)

    let dcbaap_reg_addr = (info.operational_register_address + 0x30) as *mut u64;
    unsafe {
        core::ptr::write_volatile(dcbaap_reg_addr, frame.start_address().as_u64());
    }
    Result::Ok(())
}
