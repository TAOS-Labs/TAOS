use crate::{
    devices::{mmio::MMioConstPtr, pci::{read_config, walk_pci_bus, DeviceInfo}}, events::{futures::devices::HWRegisterWrite, nanosleep_current_event}, interrupts::x2apic, memory::HHDM_OFFSET, serial_println
};

use crate::devices::audio::hda_regs::HdaRegisters;
use x86_64::structures::idt::InterruptStackFrame;
use core::ptr::{read_volatile, write_volatile};
use crate::devices::{
    audio::{
        buffer::{BdlEntry, setup_bdl},
        dma::DmaBuffer
    },
    mmio::MMioPtr
};

/// Physical BAR address (used during development before PCI scan)
/// TODO - need to find a betterr way so this variable doesnt exist
const HDA_BAR_PHYS: u32 = 0xC1040000;
const DELAY_NS :u64 = 100_000;

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
    pub async fn init() -> Option<Self> {
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
    
        hda.reset().await;
        // Set power state to D0 (0x00)
        serial_println!("Setting power state to D0 on node 0 and 3...");
        hda.send_command(0, 0, 0x705, 0x00); // Set Power State for node 0
        hda.get_response().await;
        hda.send_command(0, 3, 0x705, 0x00); // Set Power State for node 3
        hda.get_response().await;
    
        // Enable unsolicited responses early (some codecs require this before widget probing)
        hda.regs.gctl |= 1 << 8;
    
        hda.send_command(0, 0, 0xF00, 0);
        let func_group_type = hda.get_response().await;
        serial_println!("Codec node 0 function group type: 0x{:X}", func_group_type);

        serial_println!("Probing all possible widget nodes manually...");
        for node in 1..=15 {
            hda.send_command(0, node, 0xF00, 0);
            let widget_type = hda.get_response().await;
            serial_println!("Node {} widget type: 0x{:X}", node, widget_type);
        }
    
        hda.enable_pin(3).await;

        //   NEW: Set pin 3's connection to DAC node 2  
        hda.send_command(0, 3, 0x701, 0x0); // Select connection index 0 (which points to DAC node 2)
        serial_println!("Pin widget connection select set to DAC node 2");

        //   NEW: Unmute and enable output on pin 3  
        hda.send_command(0, 3, 0xF07, 0); // Get pin control
        let mut pin_ctrl = hda.get_response().await;
        serial_println!("Raw pin control (before): 0x{:X}", pin_ctrl);

        pin_ctrl |= 0xC0; // Bits 6+7: Output enable + headphone
        pin_ctrl |= 0x20; // Bit 5: Unmute
        hda.send_command(0, 3, 0x707, (pin_ctrl & 0xFF) as u8); // Set updated pin control
        serial_println!("Pin control (after enable+unmute): 0x{:X}", pin_ctrl);

        nanosleep_current_event(DELAY_NS).unwrap().await; // Short wait (0.1 ms) after change
    
        // Get Node ID range
        hda.send_command(0, 0, 0xF02, 0); // 0xF02 = Subnode count & starting ID
        let val = hda.get_response().await;
        let start_id = (val >> 0) & 0xFF;
        let total_nodes = (val >> 16) & 0xFF;
        serial_println!("Codec node 0 has {} subnodes starting at {}", total_nodes, start_id);
    
        for node in start_id..(start_id + total_nodes) {
            hda.send_command(0, node as u8, 0xF00, 0); // Widget Type
            let response = hda.get_response().await;
            serial_println!("Node {} widget type: 0x{:X}", node, response);
        }
    
        hda.send_command(0, 3, 0xF02, 0); // Get connection list length
        let conn_len = hda.get_response().await;
        serial_println!("Node 3 connection list length: 0x{:X}", conn_len);
        for i in 0..(conn_len & 0x7F) {
            hda.send_command(0, 3, 0xF02 | ((i as u16) << 8), 0); // Get connection entry i
            let conn = hda.get_response().await;
            serial_println!("Node 3 connection[{}]: 0x{:X}", i, conn);
        }

        serial_println!("Setting power state to D0 on DAC node 2...");
        hda.send_command(0, 2, 0x705, 0x00); // Power state D0
        let resp = hda.get_response().await;
        serial_println!("Power state response (node 2): 0x{:X}", resp);

    
        // Sends verb 0x706 to node 2 with stream/channel value
        // 0x10 = 0001_0000
        //  Bits 7–4 = 0x1 - Stream tag = 1 (stream #1)
        //  Bits 3–0 = 0x0 - Channel ID = 0
        // This binds node 2 to stream #1 on channel 0
        //  hopefully this is a good explanattion
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
    
        // Sends extended verb 0x02 to node 2 with stream format
        // TODO: explain 4011 fully like othher functions
        hda.set_converter_format(2, 0x4011);

        hda.regs.intctl = 1;                       // Enable global interrupts
        hda.regs.stream_regs[0].ctl |= 1 << 30;   // Enable stream interrrupt??
        hda.regs.gctl |= 1 << 8;                   // Enabble responses

        serial_println!("HDA setup complete");

        hda.send_command(0, 3, 0xF07, 0);
        let mut pin_ctrl = hda.get_response().await;
        pin_ctrl |= 0x40; // EAPD
        hda.send_command(0, 3, 0x707, (pin_ctrl & 0xFF) as u8);

        //0.1 ms delay
        nanosleep_current_event(DELAY_NS).unwrap().await;

        serial_println!("--- EAPD re-enable ---");
        serial_println!("Initial pin control read (node 3): 0x{:02X}", pin_ctrl);

        // Send another read command to double-check EAPD is actually set
        hda.send_command(0, 3, 0xF07, 0);
        let confirm_ctrl = hda.get_response().await;
        serial_println!("After setting EAPD, pin control (node 3): 0x{:02X}", confirm_ctrl);


        hda.test_dma_transfer().await; 
        Some(hda)
    }
    

    /// Resets the controller using GCTL register:
    /// - Clears and sets CRST bit (bit 0)
    pub async fn reset(&mut self) {
        unsafe {
            let gctl = &mut self.regs.gctl;

            serial_println!("GCTL before clearing CRST: 0x{:08X}", read_volatile(gctl));
            write_volatile(gctl, read_volatile(gctl) & !(1 << 0)); // Clear CRST

            HWRegisterWrite::new(gctl,0x1,0,).await;

            serial_println!("GCTL after clearing CRST:  0x{:08X}", read_volatile(gctl));
            write_volatile(gctl, read_volatile(gctl) | (1 << 0)); // Set CRST
            serial_println!("GCTL after setting CRST:   0x{:08X}", read_volatile(gctl));

            HWRegisterWrite::new(gctl,0x1,1)
            .await;

            serial_println!("CRST acknowledged by controller");

            // Delay 0.1 ms (can we safely go smaller?)
            nanosleep_current_event(DELAY_NS).unwrap().await;

            let statests = read_volatile(&self.regs.statests);
            serial_println!("STATESTS (chheckking codec presence): 0x{:X}", statests);
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

        // serial_println!("--- send_command ---");
        // serial_println!("Command: 0x{:08X}", final_command);
        // serial_println!("ICIS before: 0x{:08X}", unsafe { read_volatile(icis) });

        unsafe {
            write_volatile(icis, read_volatile(icis) & !0x1); // Clear ICB
            write_volatile(icis, read_volatile(icis) & !0x2); // Clear IRV
            write_volatile(icoi, final_command); // Write command
            // serial_println!("ICOI written");
            write_volatile(icis, read_volatile(icis) | 0x1);  // Set ICB
            // serial_println!("ICIS after setting ICB: 0x{:08X}", read_volatile(icis));
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
    pub async fn get_response(&mut self) -> u32 {
        let base = (*HHDM_OFFSET + self.base as u64).as_u64();

        let icis = MMioPtr((base + 0x68) as *mut u32);
        let icii = MMioConstPtr((base + 0x64) as *const u32);

        // TODO timeout error type similar to SDCardError for HDA
        HWRegisterWrite::new(icis.as_ptr(),0x2,2).await;

        let val = unsafe { icii.read() };
        // serial_println!("ICII (response): 0x{:08X}", val);

        unsafe {
            icis.write(icis.read() & !0x2);
        }

        val
    }

    /// Enables pin widget output (sets EAPD bit in pin control)
    pub async fn enable_pin(&mut self, node: u8) {
        self.send_command(0, node, 0xF07, 0);
        let mut pin_cntl = self.get_response().await;
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

        /// Simple test that writes data into the DMA buffer and checks LPIB/STS
        pub async fn test_dma_transfer(&mut self) {
            // use crate::devices::audio::debug::debug_hda_register_layout;
            use crate::devices::audio::dma::DmaBuffer;
            use crate::devices::audio::buffer::{setup_bdl, BdlEntry};
            use core::ptr::{read_volatile, write_volatile};
        
            serial_println!("Running DMA transfer test...");
            // debug_hda_register_layout(self.regs);
        
            let audio_buf = DmaBuffer::new(64 * 1024).expect("Failed to allocate audio buffer");
            let bdl_buf = DmaBuffer::new(core::mem::size_of::<BdlEntry>() * 32).expect("Failed BDL");
        
            for i in 0..audio_buf.size {
                unsafe {
                    *audio_buf.virt_addr.as_mut_ptr::<u8>().add(i) = if i % 2 == 0 { 0x00 } else { 0xFF };
                }
            }
        
            let bdl_ptr = bdl_buf.as_ptr::<BdlEntry>();
            let num_entries = setup_bdl(
                bdl_ptr,
                audio_buf.phys_addr.as_u64(),
                audio_buf.size as u32,
                0x1000,
            );
        
            serial_println!("setup_bdl returned {} entries", num_entries);
        
            let stream_base = &self.regs.stream_regs[0] as *const _ as *mut u8;
            let ctl_ptr = unsafe { MMioPtr(stream_base.add(0x00) as *mut u32)};
            let sts_ptr = unsafe { MMioPtr(stream_base.add(0x04) as *mut u32) };
            let lpib_ptr = unsafe { MMioPtr(stream_base.add(0x08) as *mut u32) };
            let cbl_ptr = unsafe { MMioPtr(stream_base.add(0x0C) as *mut u32) };
            let lvi_ptr = unsafe { MMioPtr(stream_base.add(0x10) as *mut u16) };
            let fmt_ptr = unsafe { MMioPtr(stream_base.add(0x14) as *mut u16) };
            let bdlpl_ptr = unsafe { MMioPtr(stream_base.add(0x18) as *mut u32) };
            let bdlpu_ptr = unsafe { MMioPtr(stream_base.add(0x1C) as *mut u32) };
            let bdl_phys = bdl_buf.phys_addr.as_u64();
        
            //   Reset stream  
            unsafe {
                ctl_ptr.write(1 << 0);
                serial_println!("Wrote CTL (SRST set): 0x{:08X}", ctl_ptr.read());
                HWRegisterWrite::new(ctl_ptr.as_ptr(), 1, 1).await;
        
                ctl_ptr.write(0);
                serial_println!("Wrote CTL (SRST cleared): 0x{:08X}", ctl_ptr.read());
                HWRegisterWrite::new(ctl_ptr.as_ptr(), 1, 0).await;
            }
        
            //Setup stream configuration  
            unsafe {
                // //SHOULD NOT BE ZERO
                fmt_ptr.write(0x4011);
                HWRegisterWrite::new(fmt_ptr.as_ptr(), 0xFFFFu16, 0x4011).await;
                serial_println!("Wrote FMT: 0x{:04X}", fmt_ptr.read());
        
                write_volatile(cbl_ptr.as_ptr(), audio_buf.size as u32);
                serial_println!("Wrote CBL: {}", cbl_ptr.read());
        
                write_volatile(lvi_ptr.as_ptr(), (num_entries - 1) as u16);
                serial_println!("Wrote LVI: {}", lvi_ptr.read());
        
                write_volatile(bdlpl_ptr.as_ptr(), bdl_phys as u32);
                serial_println!("Wrote BDLPL: 0x{:08X}", bdlpl_ptr.read());
        
                write_volatile(bdlpu_ptr.as_ptr(), (bdl_phys >> 32) as u32);
                serial_println!("Wrote BDLPU: 0x{:08X}", bdlpu_ptr.read());
            }
        
            //Tag & IOC enable  
            unsafe {
                let tag_ioc = (1 << 20) | (1 << 30);
                ctl_ptr.write(tag_ioc);
                serial_println!("Wrote CTL (tag + IOC): 0x{:08X}", ctl_ptr.read());
            }
        
            //Clear STS  
            unsafe {
                let sts = sts_ptr.read();
                sts_ptr.write(sts);
                serial_println!("Cleared STS: 0x{:08X}", sts_ptr.read());
            }
        
            //Enable DMA globally  
            unsafe {
                self.regs.gctl |= 1 << 1;
                serial_println!("GCTL after DMA enable: 0x{:08X}", read_volatile(&self.regs.gctl));
            }
        
            //RUN bit  
            unsafe {
                let val = ctl_ptr.read();
                ctl_ptr.write(val | (1 << 1));
                serial_println!("Wrote CTL (RUN): 0x{:08X}", ctl_ptr.read());
            }
        
            let ctl = unsafe { ctl_ptr.read() };
            let lpib = unsafe { lpib_ptr.read() };
            let gctl = unsafe { read_volatile(&self.regs.gctl) };
            let intsts = unsafe { read_volatile(&self.regs.intsts) };
            serial_println!(
                "After RUN -> CTL=0x{:08X}, LPIB=0x{:X}, GCTL=0x{:08X}, INTSTS=0x{:08X}",
                ctl,
                lpib,
                gctl,
                intsts
            );
        
            //Polling LPIB  
            serial_println!("Polling LPIB...");
            for _ in 0..20 {
                let lpib = unsafe { lpib_ptr.read() };
                let status = unsafe { sts_ptr.read() };
                serial_println!("LPIB: 0x{:X}, STS: 0x{:X}", lpib, status);
                nanosleep_current_event(DELAY_NS * 20).unwrap().await;
            }
        
            serial_println!("Stopping stream.");
            self.stop_stream(0);
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
