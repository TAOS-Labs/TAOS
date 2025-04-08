use crate::{devices::pci::{read_config, walk_pci_bus, DeviceInfo}, serial_println};
use alloc::vec::Vec;
use crate::devices::audio::hda_regs::HdaRegisters;


pub struct IntelHDA {
    pub base: u32,
    pub vendor_id: u16,
    pub device_id: u16,
    pub regs: &'static mut HdaRegisters,
}

impl IntelHDA {
    pub fn init() -> Option<Self> {
        let device = find_hda_device()?;
        let bar = get_bar(&device)?; ///bar means base address register where the device sits

        let regs = unsafe { &mut *(bar as *mut HdaRegisters) };


        // For now, just print basic info
        serial_println!(
            "Intel HDA found: vendor=0x{:X}, device=0x{:X}, BAR=0x{:X}",
            device.vendor_id, device.device_id, bar
        );

        Some(IntelHDA {
            base: bar,
            regs,
            vendor_id: device.vendor_id,
            device_id: device.device_id,
        })
    }

}

/// Look through PCI devices for a HDA controller
fn find_hda_device() -> Option<DeviceInfo> {
    let devices = walk_pci_bus();
    for dev in devices {
        let dev = dev.lock();
        if dev.class_code == 0x04 && dev.subclass == 0x03 {
            return Some((*dev).clone());


        }
    }
    None
}

/// Extract BAR (Base Adddress Register)
fn get_bar(device: &DeviceInfo) -> Option<u32> {
    let bar = read_config(device.bus, device.device, 0, 0x10);
    if bar & 0x1 == 0 {
        Some(bar & 0xFFFFFFF0)
    } else {
        None
    }
}
