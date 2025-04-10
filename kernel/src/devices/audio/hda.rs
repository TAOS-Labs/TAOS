use crate::{
    devices::pci::{read_config, walk_pci_bus, DeviceInfo},
    interrupts::x2apic,
    memory::HHDM_OFFSET,
    serial_println,
};

use crate::devices::audio::hda_regs::HdaRegisters;
use x86_64::structures::idt::InterruptStackFrame;
use core::ptr::{read_volatile, write_volatile};

/// Physical BAR address (used during development before PCI scan)
/// TODO - need to find a betterr way so this variable doesnt exist
const HDA_BAR_PHYS: u32 = 0xC1040000;

/// Interrupt handler for Intel HDA.
/// - Handles interrupts by reading INTSTS: interrupt status registeer (0x20) and RIRBSTS: response ring buffer status (0x5d).
/// - Clears the respective bits by writing them back.
/// - Sends EOI after handling.
pub extern "x86-interrupt" fn hda_interrupt_handler(_frame: InterruptStackFrame) {
    let virt = *HHDM_OFFSET + HDA_BAR_PHYS as u64;
    let regs = unsafe { &mut *(virt.as_u64() as *mut HdaRegisters) };

    unsafe {
        let intsts = &mut regs.intsts;
        let rirbsts = &mut regs.rirbsts;

        let int_status = read_volatile(intsts);
        let rirb_status = read_volatile(rirbsts);

        serial_println!(
            "HDA interrupt received: INTSTS=0x{:08X}, RIRBSTS=0x{:02X}",
            int_status,
            rirb_status
        );

        if int_status != 0 {
            write_volatile(intsts, int_status);
        }

        if rirb_status != 0 {
            write_volatile(rirbsts, rirb_status);
        }
    }

    x2apic::send_eoi();
}

pub struct IntelHDA {
    pub base: u32,
    pub vendor_id: u16,
    pub device_id: u16,
    pub regs: &'static mut HdaRegisters,
}

impl IntelHDA {
    /// Initializes HDA controller:
    /// - Finds the PCI device
    /// - Maps BAR to virtual address (hhdm ofset + address)
    pub fn init() -> Option<Self> {
        let device = find_hda_device()?;
        let bar = get_bar(&device)?;

        let virt = *HHDM_OFFSET + bar as u64;
        let regs = unsafe { &mut *(virt.as_u64() as *mut HdaRegisters) };

        serial_println!(
            "Intel HDA found: vendor=0x{:X}, device=0x{:X}, BAR=0x{:X} (virt: 0x{:X})",
            device.vendor_id, device.device_id, bar, virt
        );

        let mut hda = IntelHDA {
            base: bar,
            regs,
            vendor_id: device.vendor_id,
            device_id: device.device_id,
        };

        hda.reset();
        hda.send_command(0, 0, 0xF00, 0);
        let func_group_type = hda.get_response();
        serial_println!("Codec node 0 function group type: 0x{:X}", func_group_type);

        hda.enable_pin(3);

        /// Sends verb 0x706 to node 2 with stream/channel value
        /// 0x10 = 0001_0000
        ///   Bits 7–4 = 0x1 - Stream tag = 1 (stream #1)
        ///   Bits 3–0 = 0x0 - Channel ID = 0
        /// This binds node 2 to stream #1 on channel 0
        /// hopefully this is a good explanattion
        hda.set_stream_channel(2, 0x10);

        /*
        Sends extended verb 0x03 to node 2 with gain/mute configuration
        0xB035 = 1011_0000_0011_0101
          Bit 15 = 1 Apply to Right channel
          Bit 14 = 0 - Right channel NOT muted??
          Bits 13–8 = 0x30 - Gain = 48 * 0.75 dB = 36 dB (right channel) //took forever to understand this 
          Bit 7  = 1 - Apply to Left channel
          Bit 6  = 1 - Mute Left channel
          Bits 5–0 = 0x15 - Gain = 21 * 0.75 dB = 15.75 dB (left, but muted)
        Effectively: Set gain, mute left, unmute right with 36 dB gain
        */
        hda.set_amplifier_gain(2, 0xB035);

        /// Sends extended verb 0x02 to node 2 with stream format
        /// TODO: explain 4011 fully like othher functions
        hda.set_converter_format(2, 0x4011);

        unsafe {
            hda.regs.intctl = 1;                       // Enable global interrupts
            hda.regs.stream_regs[0].ctl |= 1 << 30;   // Enable stream interrrupt??
            hda.regs.gctl |= 1 << 8;                   // Enabble responses
        }

        serial_println!("HDA setup complete");
        Some(hda)
    }

    /// Resets the controller using GCTL register:
    /// - Clears and sets CRST bit (bit 0)
    pub fn reset(&mut self) {
        unsafe {
            let gctl = &mut self.regs.gctl;

            serial_println!("GCTL before clearing CRST: 0x{:08X}", read_volatile(gctl));
            write_volatile(gctl, read_volatile(gctl) & !(1 << 0)); // Clear CRST
            Self::wait_cycles(500_000);

            serial_println!("GCTL after clearing CRST:  0x{:08X}", read_volatile(gctl));
            write_volatile(gctl, read_volatile(gctl) | (1 << 0));  // Set CRST
            serial_println!("GCTL after setting CRST:   0x{:08X}", read_volatile(gctl));

            while read_volatile(gctl) & 0x1 == 0 {
                core::hint::spin_loop();
            }

            serial_println!("CRST acknowledged by controller");
            Self::wait_cycles(500_000);

            let statests = read_volatile(&self.regs.statests);
            serial_println!("STATESTS (chheckking codec presence): 0x{:X}", statests);
        }
    }

    /// timer??
    fn wait_cycles(cycles: u64) {
        for _ in 0..cycles {
            core::hint::spin_loop();
        }
    }

    /// Sends a basic verb command using ICOI (Immediate Command Output Interface) /ICIS (Immediate Command Status)
    /// Bits 31–28: Codec Address (4 bits)
    /// Bits 27–20: Node ID (8 bits)
    /// Bits 19–8 : Verb ID (12 bits)
    /// Bits 7–0  : Payload/Data (8 bits)
    pub fn send_command(&mut self, codec: u8, node: u8, command: u16, data: u8) -> bool {
        let final_command = ((codec as u32 & 0xF) << 28)
            | ((node as u32 & 0xFF) << 20)
            | ((command as u32 & 0xFFF) << 8)
            | (data as u32 & 0xFF);

        let base = (*HHDM_OFFSET + self.base as u64).as_u64();
        let icis = (base + 0x68) as *mut u32;
        let icoi = (base + 0x60) as *mut u32;

        serial_println!("--- send_command ---");
        serial_println!("Command: 0x{:08X}", final_command);
        serial_println!("ICIS before: 0x{:08X}", unsafe { read_volatile(icis) });

        unsafe {
            write_volatile(icis, read_volatile(icis) & !0x1); // Clear ICB
            write_volatile(icis, read_volatile(icis) & !0x2); // Clear IRV
            write_volatile(icoi, final_command); // Write command
            serial_println!("ICOI written");
            write_volatile(icis, read_volatile(icis) | 0x1);  // Set ICB
            serial_println!("ICIS after setting ICB: 0x{:08X}", read_volatile(icis));
        }

        true
    }

    /// Sends an extended verb command to the codec.
    /// Final 32-bit command format:
    /// Bits 31–28: Codec adddress (usually 0)
    /// Bits 27–20: Node ID (the target widget like DAC, pin, etc.)
    /// Bits 19–16: Verbb command (e.g. 0x02, 0x03)
    /// Bits 15–0 : Data (frmat info or gain settings)
    pub fn send_command_extended(&mut self, codec: u8, node: u8, command: u8, data: u16) -> bool {
        let final_command = ((codec as u32 & 0xF) << 28)
            | ((node as u32 & 0xFF) << 20)
            | ((command as u32 & 0xF) << 16)
            | (data as u32 & 0xFFFF);

        unsafe {
            let icis = &mut self.regs.icis;
            let icoi = &mut self.regs.icoi;

            write_volatile(icis, read_volatile(icis) & !0x3);
            write_volatile(icoi, final_command);
            write_volatile(icis, read_volatile(icis) | 0x1);
        }

        true
    }

    /// Reads codec response from ICII
    pub fn get_response(&mut self) -> u32 {
        let base = (*HHDM_OFFSET + self.base as u64).as_u64();
        let icis = (base + 0x68) as *mut u32;
        let icii = (base + 0x64) as *const u32;

        let mut tries = 100_000;

        while unsafe { read_volatile(icis) } & 0x2 == 0 {
            core::hint::spin_loop();
            tries -= 1;
            if tries == 0 {
                serial_println!("Timeout waiting for response");
                return 0xDEADBEEF;
            }
        }

        let val = unsafe { read_volatile(icii) };
        serial_println!("ICII (response): 0x{:08X}", val);

        unsafe {
            write_volatile(icis, read_volatile(icis) & !0x2); // Clear IRV
        }

        val
    }

    /// Enables pin widget output (sets EAPD bit in pin control)
    pub fn enable_pin(&mut self, node: u8) {
        self.send_command(0, node, 0xF07, 0);
        let mut pin_cntl = self.get_response();
        pin_cntl |= 0x40; // Set EAPD bit
        self.send_command(0, node, 0x707, (pin_cntl & 0xFF) as u8);
        serial_println!("Pin widget control set for node {}", node);
    }

    /// Sets stream/channel for node (verb 0x706)
    pub fn set_stream_channel(&mut self, node: u8, channel: u8) {
        self.send_command(0, node, 0x706, channel);
        serial_println!("Stream channel set for node {}", node);
    }

    /// Sets amplifier gain (extended verb 0x03)
    pub fn set_amplifier_gain(&mut self, node: u8, value: u16) {
        self.send_command_extended(0, node, 0x03, value);
        serial_println!("Amplifier gain set for node {}", node);
    }

    /// Sets converter format (extended verb 0x02)
    pub fn set_converter_format(&mut self, node: u8, fmt: u16) {
        self.send_command_extended(0, node, 0x02, fmt);
        serial_println!("Converter format set for node {}", node);
    }

    /// Starts audio stream (sets RUN bit in SDxCTL)
    pub fn start_stream(&mut self, stream_idx: usize) {
        unsafe {
            let ctl = &mut self.regs.stream_regs[stream_idx].ctl;
            write_volatile(ctl, read_volatile(ctl) | (1 << 1)); // RUN RUN RUN PLZ
            serial_println!("Stream {} started", stream_idx);
        }
    }

    /// Stops audio stream (clears RUN bit in SDxCTL)
    pub fn stop_stream(&mut self, stream_idx: usize) {
        unsafe {
            let ctl = &mut self.regs.stream_regs[stream_idx].ctl;
            write_volatile(ctl, read_volatile(ctl) & !(1 << 1)); // RUN STOPPPP
            serial_println!("Stream {} stopped", stream_idx);
        }
    }
}

/// Walk PCI bus to find device with Class 0x04, Subclass 0x03 (FOUND FROM OSDEV )
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

/// Reads BAR0 from PCI config space (offset 0x10) and masks off flags?
fn get_bar(device: &DeviceInfo) -> Option<u32> {
    let bar = read_config(device.bus, device.device, 0, 0x10);
    if bar & 0x1 == 0 {
        Some(bar & 0xFFFFFFF0) 
    } else {
        None
    }
}
