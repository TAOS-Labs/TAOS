use alloc::{sync::Arc, vec::Vec};
use bitflags::bitflags;
use spin::Mutex;
use x86_64::instructions::port::{
    self, PortGeneric, ReadOnlyAccess, ReadWriteAccess, WriteOnlyAccess,
};

use crate::debug_println;

/// The port used for setting the address of  PCI configuration
const CONFIG_ADDRESS_BUS: u16 = 0xCF8;
/// The port used for sending data over the PCI bus to a device
const CONFIG_DATA_BUS: u16 = 0xCFC;

/// A lock to protect access to the PCI bus
static PCI_LOCK: Mutex<()> = Mutex::new(());

bitflags! {
    #[derive(Debug, Clone, Copy)]
    /// Holds possible PCI Command values
    pub struct PCICommand: u16  {
        /// If set the device can not send an INTx# signal
        const INTERRUPT_DISABLE = 1 << 10;
        /// Set if fast back to back transactions are allowed. Read Only
        const FAST_BACK_TO_BACK_ENABLE = 1 << 9;
        /// If set the SERR# Driver is enabled
        const SERR_ENABLE = 1 << 8;
        /// If set the device will take normal action when a parity error is
        /// detected. If unset, the device will continue operation as if
        /// a parity error did not happen (but the device will still set bit 15)
        /// of the status register
        const PARITY_ERROR_RESPONSE = 1 << 6;
        /// Set the device will snoop data from pallete register writes. Read Only.
        const VGA_PALLETE_SNOOP = 1 << 5;
        /// Set if the device can issue a Memory Write and Invalidate command.
        /// Read Only
        const MEMORY_WRITE_AND_INVILIDATE_ENABLE = 1 << 4;
        /// Set if the device can monitor Special Cycle Operations. Read Only
        const SPECIAL_CYCLES = 1 << 3;
        /// If set the device can generate PCI Accesses (act as a bus master)
        const BUS_MASTER = 1 << 2;
        /// If set the evice can respond to accesses via the Memory Space
        const MEMORY_SPACE = 1 << 1;
        /// If set the device can respond to accesses via the IO Space
        const IO_SPACE = 1;
        const _ = !0;
    }
}

#[derive(Debug)]
/// A generic representation of a single funcion pci
/// device. To note
pub struct DeviceInfo {
    /// The bus that this device is on
    pub bus: u8,
    /// The device that this device is on
    pub device: u8,
    /// A Marker for the specific device that the vendor made
    pub device_id: u16,
    /// The identifier for the Manufacturer of this device
    pub vendor_id: u16,
    /// A cached status of this PCI device. If your driver expects any of
    /// these bits to change after boot, this should be re-checked
    pub status: u16,
    /// A cached status of which commands are currently active. Writing
    /// to this field has no effect, one should use the function
    /// write_pci_command
    pub command: PCICommand,
    /// The class code of the PCI device. This holds the general type of
    /// device. For example class code 0x9 is an Input Device Controller
    pub class_code: u8,
    /// Used to further differentate devices along with the class code. For
    /// example a pci device with class code 0x9 and subclass 0x0 is a
    /// Keyboard Controller
    pub subclass: u8,
    /// The programming interface that the device uses. Further differentates
    /// devices in addtion with class code and subclass
    pub programming_interface: u8,
    /// A revision identifer for this device. This code is vendor specific
    pub revision_id: u8,
    /// Represents a devices Built In Self Test.
    pub built_in_self_test: u8,
    /// Determines the layout of the rest of the PCI header. Currently only
    /// header_type 0x0 is supported (A general PCi device)
    pub header_type: u8,
    /// Says the latency timer in terms of pci bus clocks
    pub latency_timer: u8,
    /// Determines the system cache line size in 32 bit units
    pub cache_line_size: u8,
}

fn get_pci_addres(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    assert!(offset % 4 == 0);
    assert!(function < 8);
    assert!(device < 32);

    let bus_extended: u32 = bus.into();
    let device_extended: u32 = device.into();
    let function_extended: u32 = function.into();
    let offset_extended: u32 = offset.into();

    (1 << 31)
        | (bus_extended << 16)
        | (device_extended << 11)
        | (function_extended << 8)
        | offset_extended
}

/// Reads from pci config and returns the result into a u32. Note: device must be
/// less than 32, function must be less than 8, and offset must be a multiple
/// of 4.
pub fn read_config(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = get_pci_addres(bus, device, function, offset);

    PCI_LOCK.lock();
    let mut address_port: PortGeneric<u32, WriteOnlyAccess> =
        port::PortGeneric::new(CONFIG_ADDRESS_BUS);

    unsafe {
        address_port.write(address);
    }

    let mut config_port: PortGeneric<u32, ReadOnlyAccess> = port::PortGeneric::new(CONFIG_DATA_BUS);
    unsafe {
        let data = config_port.read();
        address_port.write(0);
        data
    }
}

/// Writes data to the pci bus
pub fn write_pci_data(bus: u8, device: u8, function: u8, offset: u8, data: u32) {
    let address = get_pci_addres(bus, device, function, offset);
    PCI_LOCK.lock();
    let mut address_port: PortGeneric<u32, WriteOnlyAccess> =
        port::PortGeneric::new(CONFIG_ADDRESS_BUS);
    unsafe {
        address_port.write(address);
    }

    let mut config_port: PortGeneric<u32, WriteOnlyAccess> =
        port::PortGeneric::new(CONFIG_DATA_BUS);
    unsafe {
        config_port.write(data);
        address_port.write(0);
    }
}

/// Writes the given command into the command register. It is recommended
/// to get the old value of command and set and unset the appropate bits
/// from the command, as some bits are read only
pub fn write_pci_command(bus: u8, device: u8, function: u8, command: PCICommand) {
    let address = get_pci_addres(bus, device, function, 0x4);
    PCI_LOCK.lock();
    let mut address_port: PortGeneric<u32, WriteOnlyAccess> =
        port::PortGeneric::new(CONFIG_ADDRESS_BUS);
    unsafe {
        address_port.write(address);
    }

    let mut config_port: PortGeneric<u32, ReadWriteAccess> =
        port::PortGeneric::new(CONFIG_DATA_BUS);
    let mut data: u32 = unsafe { config_port.read() };
    data &= 0xFFFF0000;
    data |= <u16 as Into<u32>>::into(command.bits());
    unsafe {
        config_port.write(data);
        address_port.write(0);
    }
}

/// Determines if a device is connected to the given bus and device pair. If
/// no device is connected then returns None. Othwewise returns data to find the
/// device in the DeviceInfo struct
fn device_connected(bus: u8, device: u8) -> Option<DeviceInfo> {
    let mut config_word = read_config(bus, device, 0, 0);
    let device_id: u16 = (config_word >> 16).try_into().expect("Masked out bits");
    let vendor_id: u16 = (config_word & 0x0000FFFF)
        .try_into()
        .expect("Masked out bits");

    if vendor_id == 0xFFFF {
        return Option::None;
    }

    config_word = read_config(bus, device, 0, 4);
    let status: u16 = (config_word >> 16).try_into().expect("Masked out bits");
    let command = PCICommand::from_bits_retain(
        (config_word & 0x0000FFFF)
            .try_into()
            .expect("Masked out bits"),
    );

    config_word = read_config(bus, device, 0, 8);
    let class_code: u8 = (config_word >> 24).try_into().expect("Masked out bits");
    let subclass: u8 = ((config_word & 0x00FF0000) >> 16)
        .try_into()
        .expect("Masked out bits");
    let programming_interface: u8 = ((config_word & 0x0000FF00) >> 8)
        .try_into()
        .expect("Masked out bits");
    let revision_id: u8 = (config_word & 0x000000FF)
        .try_into()
        .expect("Masked out bits");

    config_word = read_config(bus, device, 0, 12);
    let built_in_self_test: u8 = (config_word >> 24).try_into().expect("Masked out bits");
    let header_type: u8 = ((config_word & 0x00FF0000) >> 16)
        .try_into()
        .expect("Masked out bits");
    let latency_timer: u8 = ((config_word & 0x0000FF00) >> 8)
        .try_into()
        .expect("Masked out bits");
    let cache_line_size: u8 = (config_word & 0x000000FF)
        .try_into()
        .expect("Masked out bits");

    let device_info = DeviceInfo {
        bus,
        device,
        device_id,
        vendor_id,
        status,
        command,
        class_code,
        subclass,
        programming_interface,
        revision_id,
        built_in_self_test,
        header_type,
        latency_timer,
        cache_line_size,
    };
    Option::Some(device_info)
}

/// A debug funcion to print data we have collected on a device
pub fn print_pci_info(device: &DeviceInfo) {
    debug_println!("----------");
    debug_println!("bus = {}", { device.bus });
    debug_println!("device = {}", { device.device });
    debug_println!("device_id = 0x{:X}", { device.device_id });
    debug_println!("vendor_id = 0x{:X}", { device.vendor_id });
    debug_println!("status = 0x{:X}", { device.status });
    debug_println!("class_code = 0x{:X}", { device.class_code });
    debug_println!("subclass = 0x{:X}", { device.subclass });
    debug_println!("programming_interface = 0x{:X}", {
        device.programming_interface
    });
}

/// Determines all devices connected to the PCI bus. Does not currently have
/// support for multi function devices.
pub fn walk_pci_bus() -> Vec<Arc<Mutex<DeviceInfo>>> {
    let mut bus: u16 = 0;
    let mut devices = Vec::new();
    while bus < 256 {
        let mut device: u8 = 0;
        while device < 32 {
            match device_connected(bus.try_into().expect("Masked out bits"), device) {
                None => (),
                Some(device_info) => {
                    devices.push(Arc::new(Mutex::new(device_info)));
                }
            }
            device += 1
        }
        bus += 1
    }
    devices
}
