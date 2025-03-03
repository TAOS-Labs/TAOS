pub mod context;
pub mod ring_buffer;

use core::cmp::min;

use crate::{debug_println, memory::frame_allocator::FRAME_ALLOCATOR};
use alloc::{sync::Arc, vec::Vec};
use bitflags::bitflags;
use spin::Mutex;
use x86_64::{
    structures::paging::{FrameAllocator, OffsetPageTable, Page},
    VirtAddr,
};

use super::{
    mmio,
    pci::{read_config, DeviceInfo},
};

const MAX_USB_DEVICES: u8 = 4;

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

    let info = initalize_xhciinfo(full_bar, mapper)?;
    // Turn on device

    let command_register_address = info.operational_register_address as *mut u32;
    let mut command_data = CommandRegister::from_bits_retain(unsafe {
        core::ptr::read_volatile(command_register_address)
    });
    command_data = command_data.union(CommandRegister::RunHostControler);
    unsafe {
        core::ptr::write_volatile(command_register_address, command_data.bits());
    }

    debug_println!("0x{:X} {:?}", { info.base_address }, { info.capablities });
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
    let address = mmio::map_page_as_uncacheable(full_bar, mapper).unwrap();
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
    let mut allator_tmp = FRAME_ALLOCATOR.lock();
    let allocator = allator_tmp.as_mut().ok_or(XHCIError::NoFrameAllocator)?;
    let frame = allocator
        .allocate_frame()
        .ok_or(XHCIError::MemoryAllocationFailure)?;
    let virtual_adddr = mmio::map_page_as_uncacheable(frame.start_address().as_u64(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;

    // We need to zero out shit
    mmio::zero_out_page(Page::containing_address(VirtAddr::new(virtual_adddr)));

    // set DCBAAP (Device Context Base Array Pointer Register)
    let dcbaap_reg_addr = (operational_start + 0x30) as *mut u64;
    unsafe {
        core::ptr::write_volatile(dcbaap_reg_addr, frame.start_address().as_u64());
    }

    // Allocate space for the Command Ring.
    let cmd_frame = allocator
        .allocate_frame()
        .ok_or(XHCIError::MemoryAllocationFailure)?;
    let cmd_vaddr = mmio::map_page_as_uncacheable(cmd_frame.start_address().as_u64(), mapper)
        .map_err(|_| XHCIError::MemoryAllocationFailure)?;

    // We need to zero out this page as well
    mmio::zero_out_page(Page::containing_address(VirtAddr::new(cmd_vaddr)));

    // set Command Ring Control reg to starting addr of command ring.
    let crcreg_addr = (operational_start + 0x18) as *mut u64;
    let crcreg_value = cmd_frame.start_address().as_u64() | 1;
    unsafe {
        core::ptr::write_volatile(crcreg_addr, crcreg_value);
    }

    Result::Ok(XHCIInfo {
        base_address: address,
        capablities,
        operational_register_address: operational_start,
        base_address_array: frame.start_address().as_u64(),
        command_ring_base: cmd_frame.start_address().as_u64(),
    })
}

#[cfg(test)]
mod test {
    use super::{
        ring_buffer::{RingBuffer, RingType, Trb, TrbTypes},
        *,
    };
    use crate::{
        devices::xhci::ring_buffer::RingBufferError,
        memory::{
            paging::{create_mapping, remove_mapped_frame},
            MAPPER,
        },
    };

    #[test_case]
    fn ring_buffer_init() {
        // first get a page and zero init it
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // call the new function
        let base_addr = page.start_address().as_u64();
        let size = page.size() as isize;
        let _cmd_ring =
            RingBuffer::new(base_addr, 1, RingType::Command, size).expect("Intialization failed");

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
    fn ring_buffer_enqueue() {
        // initialize a ring buffer we can enqueue onto
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // call the new function
        let base_addr = page.start_address().as_u64();
        let size = page.size() as isize;
        let mut cmd_ring =
            RingBuffer::new(base_addr, 1, RingType::Command, size).expect("Intialization failed");

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
    fn ring_buffer_dequeue() {
        // initialize a ring buffer we can dequeue from
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // call the new function
        let base_addr = page.start_address().as_u64();
        let size = page.size() as isize;
        let mut event_ring =
            RingBuffer::new(base_addr, 1, RingType::Event, size).expect("Intialization failed");

        // first put the block onto the queue
        let ring_base = base_addr as *mut Trb;
        let expect_stat: u32 = 0x1000000;
        let mut expected_trb = Trb {
            parameters: 0,
            status: expect_stat,
            control: 0,
        };
        let expect_control: u32 = 0x9401;
        expected_trb.set_trb_type(TrbTypes::HcEvent as u32);
        expected_trb.set_cycle(1);

        // insert the expected trb, set the enqueue pointer down the line to allow us to dequeue and then dequeue
        let deq_trb: Trb;
        unsafe {
            *ring_base = expected_trb;
            event_ring
                .set_enqueue(base_addr + 16)
                .expect("enqueue error");
            deq_trb = event_ring.dequeue().expect("dequeue failed");
        }

        // check the trb we got back
        let params = deq_trb.parameters;
        let status = deq_trb.status;
        let control = deq_trb.control;

        assert_eq!(params, 0);
        assert_eq!(status, expect_stat);
        assert_eq!(control, expect_control);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn ring_buffer_helpers() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // create a small ring buffer
        let base_addr = page.start_address().as_u64();
        let size: isize = 64;
        let mut cmd_ring =
            RingBuffer::new(base_addr, 1, RingType::Command, size).expect("Intialization failed");

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
    fn ring_buffer_errors() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // First test the new function with unaligned address
        let mut base_addr = page.start_address().as_u64();
        base_addr += 1;
        let mut size: isize = 64;
        let mut result = RingBuffer::new(base_addr, 1, RingType::Command, size).unwrap_err();

        assert_eq!(result, RingBufferError::UnalignedAddress);

        // now test with unaligned size
        base_addr -= 1;
        size += 5;
        result = RingBuffer::new(base_addr, 1, RingType::Command, size).unwrap_err();

        assert_eq!(result, RingBufferError::UnalignedSize);
        size -= 5;

        // make an actual proper cmd ring
        let mut cmd_ring =
            RingBuffer::new(base_addr, 1, RingType::Command, size).expect("Intialization failed");

        // now begin testing the setters for unaligned address
        result = cmd_ring.set_enqueue(base_addr + 18).unwrap_err();
        assert_eq!(result, RingBufferError::UnalignedAddress);

        result = cmd_ring.set_dequeue(base_addr + 18).unwrap_err();
        assert_eq!(result, RingBufferError::UnalignedAddress);

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
        assert_eq!(result, RingBufferError::BufferFullError);

        // test dequeue invalid type error
        unsafe {
            result = cmd_ring.dequeue().unwrap_err();
        }
        assert_eq!(result, RingBufferError::InvalidType);

        // create an event buffer so we can test the rest of the errors
        let mut event_ring =
            RingBuffer::new(base_addr, 1, RingType::Event, size).expect("init failed");

        // test enqueue invalid type err
        unsafe {
            result = event_ring.enqueue(cmd).unwrap_err();
        }
        assert_eq!(result, RingBufferError::InvalidType);

        // try to dequeue when it is empty
        unsafe {
            result = event_ring.dequeue().unwrap_err();
        }
        assert_eq!(result, RingBufferError::BufferEmptyError);

        remove_mapped_frame(page, &mut *mapper);
    }

    #[test_case]
    fn ring_buffer_enqueue_accross_segment() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // create a small ring buffer
        let base_addr = page.start_address().as_u64();
        let size: isize = 64;
        let mut cmd_ring =
            RingBuffer::new(base_addr, 1, RingType::Command, size).expect("Intialization failed");

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
    fn ring_buffer_dequeue_accross_segment() {
        let mut mapper = MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        mmio::zero_out_page(page);

        // create a small ring buffer
        let base_addr = page.start_address().as_u64();
        let size: isize = 64;
        let mut event_ring =
            RingBuffer::new(base_addr, 1, RingType::Event, size).expect("Intialization failed");

        // move dequeue to point to block preceding link trb
        event_ring
            .set_dequeue(base_addr + 32)
            .expect("unalgined address");

        // dequeue should change the internal pointer to be the base address
        unsafe {
            event_ring.dequeue().expect("dequeue error");
        }

        // we can test this by seeing that the ring is empty since the enqueue pointer hasnt moved
        assert!(event_ring.is_ring_empty());

        remove_mapped_frame(page, &mut *mapper);
    }
}
