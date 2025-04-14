use crate::{
    devices::{
        mmio::MMioConstPtr,
        pci::{read_config, walk_pci_bus, DeviceInfo},
    }, events::{futures::devices::HWRegisterWrite, nanosleep_current_event}, interrupts::x2apic, memory::HHDM_OFFSET, serial, serial_println
};

use crate::devices::{
    audio::{
        buffer::{setup_bdl, BdlEntry},
        dma::DmaBuffer,
        hda_regs::HdaRegisters,
    },
    mmio::MMioPtr,
};
use core::{future::Future, mem::offset_of, pin::Pin, ptr::{read_volatile, write_volatile}};
use alloc::{boxed::Box, vec};
use alloc::vec::Vec;
use x86_64::structures::idt::InterruptStackFrame;
use crate::devices::audio::widget_info::WidgetInfo;


/// Physical BAR address (used during development before PCI scan)
/// TODO - need to find a betterr way so this variable doesnt exist
const HDA_BAR_PHYS: u32 = 0xC1040000;
const DELAY_NS: u64 = 100_000;

/// Interrupt handler for Intel HDA.
/// - Handles interrupts by reading INTSTS: interrupt status registeer (0x20) and RIRBSTS: response ring buffer status (0x5d).
/// - Clears the respective bits by writing them back.
/// - Sends EOI after handling.

pub extern "x86-interrupt" fn hda_interrupt_handler(_frame: InterruptStackFrame) {
    let virt = *HHDM_OFFSET + HDA_BAR_PHYS as u64;
    let regs = unsafe { &*(virt.as_u64() as *const HdaRegisters) };

    let regs_base = regs as *const _ as *const u8;
    let intsts_ptr = unsafe { regs_base.add(offset_of!(HdaRegisters, intsts)) as *mut u32 };
    let rirbsts_ptr = unsafe { regs_base.add(offset_of!(HdaRegisters, rirbsts)) as *mut u8 };

    unsafe {
        let int_status = read_volatile(intsts_ptr);
        let rirb_status = read_volatile(rirbsts_ptr);

        serial_println!(
            "HDA interrupt received: INTSTS=0x{:08X}, RIRBSTS=0x{:02X}",
            int_status,
            rirb_status
        );

        if int_status != 0 {
            write_volatile(intsts_ptr, int_status);
        }

        if rirb_status != 0 {
            write_volatile(rirbsts_ptr, rirb_status);
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
            device.vendor_id,
            device.device_id,
            bar,
            virt
        );
    
        let mut hda = IntelHDA {
            base: bar,
            regs,
            vendor_id: device.vendor_id,
            device_id: device.device_id,
        };

        serial_println!("BASE: 0x{:08X}", hda.base);

        hda.regs.gctl |= 1 << 8;
        hda.reset().await;
    
        // Verb: 0xF81 = Set Power State + Init
        hda.send_command(0, 0, 0xF81, 0x00);
        let resp = hda.get_response().await;
        serial_println!("SigmaTel codec kickstart response: 0x{:X}", resp);

        hda.send_command(0, 1, 0xF81, 0x00); // try node 1 (AFG)

    
        // Set power state to D0 (0x00)
        serial_println!("Setting power state to D0 on node 0 and 3");
        hda.send_command(0, 0, 0x705, 0x00); // Set Power State for node 0
        hda.get_response().await;
        hda.send_command(0, 3, 0x705, 0x00); // Set Power State for node 3
        hda.get_response().await;

        nanosleep_current_event(DELAY_NS * 2000).unwrap().await;

    
        // Enable unsolicited responses early (some codecs require this before widget probing?)
        hda.regs.gctl |= 1 << 8;
    
        // Run full codec and widget discovery (may be empty if widget types still return 0)
        let widget_list = hda.probe_afg_and_widgets().await;
        serial_println!("Total widgets discovered: {}", widget_list.len());

        // let widget_list = Self::force_known_widgets().await;
        // serial_println!("(Forced) Using {} known widgets", widget_list.len());
    
        hda.send_command(0, 0, 0xF00, 0);
        let func_group_type = hda.get_response().await;
        serial_println!("Codec node 0 function group type: 0x{:X}", func_group_type);
    
        serial_println!("Probing all possible widget nodes manually...");
        for node in 1..=15 {
            hda.send_command(0, node, 0xF00, 0);
            let widget_type = hda.get_response().await;
            serial_println!("Node {} widget type: 0x{:X}", node, widget_type);
            serial_println!("Node {} widget type: 0x{:X} ({})", node, widget_type, IntelHDA::decode_widget_type(widget_type));

        }
    
        hda.enable_pin(3).await;
    
        //Set pin 3's connection to DAC node 2 //doing this manually cause all the widgets arer 0
        hda.send_command(0, 3, 0x701, 0x0); // Select connection index 0 (which points to DAC node 2)
        serial_println!("Pin widget connection select set to DAC node 2");

        // Trace the full path from pin 3 to DAC (for verification/debug)
        serial_println!("___________TRACE_____________");
        if let Some(path) = hda.trace_path_to_dac(3).await {
            serial_println!("Traced path from pin node 3 to DAC: {:?}", path);
        } else {
            serial_println!("Failed to trace path from pin to DAC.");
        }
    
        // Unmute and enable output on pin 3
        hda.send_command(0, 3, 0xF07, 0); // Get pin control
        let mut pin_ctrl = hda.get_response().await;
        serial_println!("Raw pin control (before): 0x{:X}", pin_ctrl);
    
        pin_ctrl |= 0xC0; // Bits 6+7: Output enable + headphone
        pin_ctrl |= 0x20; // Bit 5: Unmute
        hda.send_command(0, 3, 0x707, (pin_ctrl & 0xFF) as u8); // Set updated pin control
        serial_println!("Pin control (after enable+unmute): 0x{:X}", pin_ctrl);

        hda.send_command(0, 3, 0x1C, 0); // Get default config
        let config_default = hda.get_response().await;
        let def_device = (config_default >> 20) & 0xF;
        let def_device_name = match def_device {
            0x0 => "Line Out",
            0x1 => "Speaker",
            0x2 => "HP Out",
            _ => "Other",
        };
        serial_println!("Pin node 3 default device: {} (0x{:X})", def_device_name, def_device);

    
        nanosleep_current_event(DELAY_NS).unwrap().await; // Short wait (0.1 ms) after change
    
        // Get Node ID range
        hda.send_command(0, 0, 0xF02, 0); // 0xF02 = Subnode count & starting ID
        let val = hda.get_response().await;
        let start_id = (val >> 0) & 0xFF;
        let total_nodes = (val >> 16) & 0xFF;
        serial_println!(
            "Codec node 0 has {} subnodes starting at {}",
            total_nodes,
            start_id
        );
    
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
    
        //trying with node 2 now
        serial_println!("Setting power state to D0 on DAC node 2");
        hda.send_command(0, 2, 0x705, 0x00); // Power state D0
        let resp = hda.get_response().await;
        serial_println!("Power state response (node 2): 0x{:X}", resp);

        hda.send_command(0, 2, 0xF05, 0); // Get power state
        let state = hda.get_response().await;
        serial_println!("DAC node 2 current power state: 0x{:X}", state);

    
        hda.set_stream_channel(2, 0x10);

    
        /*
        Sends extended verb 0x03 to node 2 with gain/mute configuration
        0xB035 = 1011_0000_0011_0101
        */
        hda.set_amplifier_gain(2, 0xB035);
    
        // Sends extended verb 0x02 to node 2 with stream format
        hda.set_converter_format(2, 0x4011);
    
        hda.regs.intctl = 1; // Enable global interrupts
        hda.regs.stream_regs[0].ctl0 |= 1 << 2; // Enable stream interrupt
        hda.regs.gctl |= 1 << 8; // Enable unsolicited responses
    
        serial_println!("HDA setup complete");
    
        hda.send_command(0, 3, 0xF07, 0);
        let mut pin_ctrl = hda.get_response().await;
        pin_ctrl |= 0x40; // EAPD
        hda.send_command(0, 3, 0x707, (pin_ctrl & 0xFF) as u8);
    
        nanosleep_current_event(DELAY_NS).unwrap().await;
    
        serial_println!("--- EAPD re-enable ---");
        serial_println!("Initial pin control read (node 3): 0x{:02X}", pin_ctrl);
    
        hda.send_command(0, 3, 0xF07, 0);
        let confirm_ctrl = hda.get_response().await;
        serial_println!(
            "After setting EAPD, pin control (node 3): 0x{:02X}",
            confirm_ctrl
        );
    
        hda.test_dma_transfer().await;
        Some(hda)
    }

    fn decode_widget_type(val: u32) -> &'static str {
        match val & 0xF {
            0x0 => "Audio Output (DAC)",
            0x1 => "Audio Input (ADC)",
            0x2 => "Mixer",
            0x3 => "Selector",
            0x4 => "Pin Complex",
            0x5 => "Power",
            0x6 => "Volume Knob",
            0x7 => "Beep Generator",
            0x8 => "Vendor Specific",
            _ => "Unknown",
        }
    }
    
    pub async fn force_known_widgets() -> Vec<WidgetInfo> {
        let mut widgets = Vec::new();
    
        let mut dac = WidgetInfo::new(2);
        dac.widget_type = 1; // 0x1 = DAC
        dac.amp_out_caps = 0xFFFFFFFF; 
        widgets.push(dac);
    
        let mut pin = WidgetInfo::new(3);
        pin.widget_type = 4; // 0x4 = Pin
        pin.conn_list.push(2); // Connect to DAC node 2
        widgets.push(pin);
    
        widgets
    }

    pub async fn probe_afg_and_widgets(&mut self) -> Vec<WidgetInfo> {
        let mut widgets = Vec::new();
    
        // Attempt to find AFG properly
        self.send_command(0, 0, 0xF00, 4); // Get function group count
        let fg_count_raw = self.get_response().await;
        let fg_count = fg_count_raw & 0xFF;
        serial_println!("Function group count: {}", fg_count);
    
        let mut afg_nid = None;
        for i in 1..=fg_count {
            self.send_command(0, i as u8, 0xF00, 5); // Check function group type
            let group_type = self.get_response().await;
            serial_println!("Func group node {} type: 0x{:X}", i, group_type);
    
            if (group_type & 0xF) == 0x01 {
                afg_nid = Some(i as u8);
                break;
            }
        }
    
        let afg_node = match afg_nid {
            Some(nid) => nid,
            None => {
                serial_println!("No AFG found!");
                return widgets;
            }
        };
        serial_println!("AFG found at node {}", afg_node);
    
        //Try to get subnode range (but may fail!)
        self.send_command(0, afg_node, 0xF02, 0);
        let val = self.get_response().await;
        let start_id = (val >> 0) & 0xFF;
        let total_nodes = (val >> 16) & 0xFF;
    
        if total_nodes == 0 {
            serial_println!("AFG {} has 0 subnodes — using brute-force widget scan", afg_node);
        } else {
            serial_println!(
                "AFG {} has {} subnodes starting at {}",
                afg_node,
                total_nodes,
                start_id
            );
        }
    
        //Brute-force check widget types for 1..=63 (safe upper bound)
        for node in 1..=63 {
            self.send_command(0, node as u8, 0xF00, 0); // Widget type
            let wtype = self.get_response().await;
    
            if wtype == 0 {
                continue; // No widget here
            }
    
            let mut w = WidgetInfo::new(node as u8);
            w.widget_type = wtype;
    
            self.send_command(0, node as u8, 0x0C, 0); // Pin capabilities
            w.pin_caps = self.get_response().await;
    
            self.send_command(0, node as u8, 0x0D, 0); // Input Amp
            w.amp_in_caps = self.get_response().await;
    
            self.send_command(0, node as u8, 0x12, 0); // Output Amp
            w.amp_out_caps = self.get_response().await;
    
            self.send_command(0, node as u8, 0x13, 0); // Volume knob
            w.volume_knob = self.get_response().await;
    
            self.send_command(0, node as u8, 0x1C, 0); // Default config
            w.config_default = self.get_response().await;
    
            self.send_command(0, node as u8, 0x0E, 0); // Conn list len
            let conn_len = self.get_response().await & 0x7F;
    
            for i in 0..conn_len {
                self.send_command(0, node as u8, 0xF02 | ((i as u16) << 8), 0);
                let conn = self.get_response().await;
                w.conn_list.push(conn as u8);
            }
    
            serial_println!(
                "Discovered widget: NID={} type=0x{:X}, connections={:?}",
                w.nid,
                w.widget_type,
                w.conn_list
            );
    
            widgets.push(w);
        }
        let nonzero_widgets: Vec<_> = widgets.iter().filter(|w| w.widget_type != 0).collect();
        if nonzero_widgets.is_empty() {
            serial_println!("All widgets returned 0 — codec likely not present or not initialized correctly.");
        }

    
        widgets
    }

    pub async fn trace_path_to_dac(&mut self, start: u8) -> Option<Vec<u8>> {
        use alloc::vec::Vec;
        let mut stack: Vec<(u8, Vec<u8>)> = Vec::new();
        stack.push((start, vec![start]));
    
        while let Some((node, path)) = stack.pop() {
            self.send_command(0, node, 0xF00, 0);
            let widget_type = self.get_response().await;
    
            if widget_type & 0xF == 0x0 {
                return Some(path); // Found DAC
            }
    
            self.send_command(0, node, 0xF02, 0); // Conn list len
            let conn_len = self.get_response().await & 0x7F;
    
            for i in 0..conn_len {
                self.send_command(0, node, 0xF02 | ((i as u16) << 8), 0);
                let conn_node = self.get_response().await as u8;
                let mut new_path = path.clone();
                new_path.push(conn_node);
                stack.push((conn_node, new_path));
            }
        }
    
        None
    }
    
    
        
    /// Resets the controller using GCTL register:
    /// - Clears and sets CRST bit (bit 0)
    pub async fn reset(&mut self) {
        unsafe {
            let gctl_ptr = MMioPtr((self.regs as *const _ as *const u8).add(offset_of!(HdaRegisters, gctl)) as *mut u32);
            let gctl = gctl_ptr.read();

            serial_println!("GCTL before clearing CRST: 0x{:08X}", gctl_ptr.read());


            gctl_ptr.write(gctl & !(1 << 0));
            HWRegisterWrite::new(gctl_ptr.as_ptr(), 0x1, 0).await;

            let gctl = gctl_ptr.read();
            serial_println!("GCTL after clearing CRST:  0x{:08X}", gctl);
            
            gctl_ptr.write(gctl | (1 << 0));        // THIS IS THE CULPRIT <------
            serial_println!(
                "GCTL after setting CRST:   0x{:08X}",
                 gctl_ptr.read()
            );

            HWRegisterWrite::new(gctl_ptr.as_ptr(), 0x1, 1).await;
            nanosleep_current_event(500_000).unwrap().await; // wait 0.5 ms


            serial_println!("CRST acknowledged by controller");

            // Delay 0.1 ms (can we safely go smaller?)
            nanosleep_current_event(3_000_000).unwrap().await;


            let statests_ptr = (self.regs as *const _ as *const u8).add(offset_of!(HdaRegisters, statests)) as *const u16;
            let statests = core::ptr::read_volatile(statests_ptr);
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
        let icis = (base + offset_of!(HdaRegisters, icis) as u64) as *mut u32;  // TODO double check this calc?
        let icoi = (base + offset_of!(HdaRegisters, icoi) as u64) as *mut u32;

        // serial_println!("Base: 0x{:08X} Offset 0x{:08X}", self.base, offset_of!(HdaRegisters, icis));

        // serial_println!("--- send_command ---");
        // serial_println!("Command: 0x{:08X}", final_command);
        // serial_println!("ICIS before: 0x{:08X}", unsafe { read_volatile(icis) });

        unsafe {
            write_volatile(icis, read_volatile(icis) & !0x1); // Clear ICB
            write_volatile(icis, read_volatile(icis) & !0x2); // Clear IRV
            write_volatile(icoi, final_command); // Write command
            // serial_println!("ICOI written");
            write_volatile(icis, read_volatile(icis) | 0x1); // Set ICB
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
            let icis_ptr = (self.regs as *const _ as *const u8).add(offset_of!(HdaRegisters, icis)) as *mut u32;
            let icoi_ptr = (self.regs as *const _ as *const u8).add(offset_of!(HdaRegisters, icoi)) as *mut u32;

            write_volatile(icis_ptr, read_volatile(icis_ptr) & !0x3);
            write_volatile(icoi_ptr, final_command);
            write_volatile(icis_ptr, read_volatile(icis_ptr) | 0x1);
        }

        true
    }

    /// Reads codec response from ICII
    pub async fn get_response(&mut self) -> u32 {
        let base = (*HHDM_OFFSET + self.base as u64).as_u64();

        let icis = MMioPtr((base + offset_of!(HdaRegisters, icis) as u64) as *mut u32);
        let icii = MMioConstPtr((base + offset_of!(HdaRegisters, icii) as u64) as *const u32);

        // TODO timeout error type similar to SDCardError for HDA
        // serial_println!("Waiting for ICIS IRV to be set");
        HWRegisterWrite::new(icis.as_ptr(), 0x2, 2).await;
        // serial_println!("ICIS IRV set!");


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
            let ctl = &mut self.regs.stream_regs[stream_idx].ctl0;
            write_volatile(ctl, read_volatile(ctl) | (1 << 1)); // RUN RUN RUN PLZ
            serial_println!("Stream {} started", stream_idx);
        }
    }

    /// Stops audio stream (clears RUN bit in SDxCTL)
    pub fn stop_stream(&mut self, stream_idx: usize) {
        unsafe {
            let ctl = &mut self.regs.stream_regs[stream_idx].ctl0;
            write_volatile(ctl, read_volatile(ctl) & !(1 << 1)); // RUN STOPPPP
            serial_println!("Stream {} stopped", stream_idx);
        }
    }

    /// Simple test that writes data into the DMA buffer and checks LPIB/STS
    pub async fn test_dma_transfer(&mut self) {
        use crate::devices::audio::{
            buffer::{setup_bdl, BdlEntry},
            dma::DmaBuffer,
        };
        use core::ptr::{read_volatile, write_volatile};
    
        serial_println!("Running DMA transfer test...");
    
        let audio_buf = DmaBuffer::new(64 * 1024).expect("Failed to allocate audio buffer");
        let bdl_buf = DmaBuffer::new(core::mem::size_of::<BdlEntry>() * 32).expect("Failed BDL");
    
        for i in 0..audio_buf.size {
            unsafe {
                *audio_buf.virt_addr.as_mut_ptr::<u8>().add(i) =
                    if i % 2 == 0 { 0x00 } else { 0xFF };
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

        for i in 0..16 {
            let b = unsafe { *(audio_buf.virt_addr.as_u64() as *const u8).add(i) };
            serial_println!("Audio buf[{}] = {:02X}", i, b);
        }
        

        let regs_base = MMioPtr(self.regs as *const _ as *mut u8);
    
        let stream_base = &self.regs.stream_regs[0] as *const _ as *mut u8;
        let ctl1_ptr = unsafe { MMioPtr(stream_base.add(0x00) as *mut u8) };
        let ctl2_ptr = unsafe { MMioPtr(stream_base.add(0x02) as *mut u8) };
        let sts_ptr = unsafe { MMioPtr(stream_base.add(0x03) as *mut u8) };
        let lpib_ptr = unsafe { MMioPtr(stream_base.add(0x04) as *mut u32) };
        let cbl_ptr = unsafe { MMioPtr(stream_base.add(0x08) as *mut u32) };
        let lvi_ptr = unsafe { MMioPtr(stream_base.add(0x0C) as *mut u16) };
        let fmt_ptr = unsafe { MMioPtr(stream_base.add(0x12) as *mut u16) };
        let bdlpl_ptr = unsafe { MMioPtr(stream_base.add(0x18) as *mut u32) };
        let bdlpu_ptr = unsafe { MMioPtr(stream_base.add(0x1C) as *mut u32) };
        let bdl_phys = bdl_buf.phys_addr.as_u64();

        serial_println!("---------------------------------------------------------");
        serial_println!("FMT pointer address: 0x{:X}", fmt_ptr.as_ptr() as usize);
        let base = &self.regs.stream_regs[0] as *const _ as usize;
        serial_println!("Stream 0 base address: 0x{:X}", base);
        serial_println!("Expected FMT offset from base: 0x12");
        serial_println!("→ Should be at: 0x{:X}", base + 0x12);
        serial_println!("---------------------------------------------------------");


    
        // Reset stream
        unsafe {
            ctl1_ptr.write(1 << 0);
            serial_println!("Wrote CTL (SRST set): 0x{:08X}", ctl1_ptr.read());
            HWRegisterWrite::new(ctl1_ptr.as_ptr(), 1, 1).await;
    
            ctl1_ptr.write(0);
            serial_println!("Wrote CTL (SRST cleared): 0x{:08X}", ctl1_ptr.read());
            HWRegisterWrite::new(ctl1_ptr.as_ptr(), 1, 0).await;
        }
    
        // Stream configuration
        unsafe {
            write_volatile(fmt_ptr.as_ptr(), 0x4011);
            HWRegisterWrite::new(fmt_ptr.as_ptr(), 0xFFFFu16, 0x4011).await;
            serial_println!("Wrote FMT: 0x{:04X}", fmt_ptr.read());
    
            write_volatile(cbl_ptr.as_ptr(), audio_buf.size as u32);
            serial_println!("Wrote CBL: {}", cbl_ptr.read());
    
            write_volatile(lvi_ptr.as_ptr(), (num_entries - 1) as u16);
            serial_println!("Wrote LVI: {}", lvi_ptr.read());
    
            //Correct ordering of BDLPL and BDLPU
            write_volatile(bdlpl_ptr.as_ptr(), (bdl_phys & 0xFFFFFFFF) as u32);
            serial_println!("Wrote BDLPL: 0x{:08X}", bdlpl_ptr.read());

            write_volatile(bdlpu_ptr.as_ptr(), (bdl_phys >> 32) as u32);// High bits = 0 for 32-bit address
            serial_println!("Wrote BDLPU: 0x{:08X}", bdlpu_ptr.read());
        }
    
        // Tag & IOC enable
        unsafe {
            let tag_ioc = 1 << 4;
            ctl2_ptr.write(tag_ioc);
            serial_println!("Wrote CTL (tag + IOC): 0x{:08X}", ctl2_ptr.read());
        }
    
        // Clear STS
        unsafe {
            let sts = sts_ptr.read();
            sts_ptr.write(sts);
            serial_println!("Cleared STS: 0x{:08X}", sts_ptr.read());
        }
    
        // Enable global DMA

        let gctl_ptr = unsafe { regs_base.add(offset_of!(HdaRegisters, gctl)) };
        unsafe {
            let current = gctl_ptr.read();
            gctl_ptr.write(current | (1 << 1));
            serial_println!(
                "GCTL after DMA enable: 0x{:08X}",
                gctl_ptr.read()
            );
        }
    
        // Start stream (RUN | DEIE | FEIE)
        unsafe {
            let val = ctl1_ptr.read();
            let new_ctl = val | (1 << 1) | (1 << 2) | (1 << 3);
            ctl1_ptr.write(new_ctl);
            serial_println!("Wrote CTL (RUN | DEIE | FEIE): 0x{:08X}", ctl1_ptr.read());
        }
    
        // Dump stream register state
        let sd_base = &self.regs.stream_regs[0] as *const _ as *const u8;

        let ctl0 = unsafe { read_volatile(sd_base.add(0x00) as *const u8) };
        let ctl1 = unsafe { read_volatile(sd_base.add(0x01) as *const u8) };
        let ctl2 = unsafe { read_volatile(sd_base.add(0x02) as *const u8) };
        let ctl_val = (ctl0 as u32) | ((ctl1 as u32) << 8) | ((ctl2 as u32) << 16);

        let sts    = unsafe { read_volatile(sd_base.add(0x03) as *const u8) };
        let lpib   = unsafe { read_volatile(sd_base.add(0x04) as *const u32) };
        let cbl    = unsafe { read_volatile(sd_base.add(0x08) as *const u32) };
        let lvi    = unsafe { read_volatile(sd_base.add(0x0C) as *const u16) };
        let fmt    = unsafe { read_volatile(sd_base.add(0x12) as *const u16) };
        let bdlpl  = unsafe { read_volatile(sd_base.add(0x18) as *const u32) };
        let bdlpu  = unsafe { read_volatile(sd_base.add(0x1C) as *const u32) };

        serial_println!("--- SD0 Register Dump ---");
        serial_println!("CTL   : 0x{:08X}", ctl_val);
        serial_println!("STS   : 0x{:02X}", sts);
        serial_println!("LPIB  : 0x{:08X}", lpib);
        serial_println!("CBL   : 0x{:08X}", cbl);
        serial_println!("LVI   : 0x{:04X}", lvi);
        serial_println!("FMT   : 0x{:04X}", fmt);
        serial_println!("BDLPL : 0x{:08X}", bdlpl);
        serial_println!("BDLPU : 0x{:08X}", bdlpu);

        // Other values (no change needed if not from packed struct)
        let ctl = unsafe { (ctl1_ptr.read() as u32) | ((ctl2_ptr.read() as u32) << 16) };
        
        let gctl_ptr = unsafe { regs_base.add(offset_of!(HdaRegisters, gctl)) };
        let intsts_ptr = unsafe { regs_base.add(offset_of!(HdaRegisters, intsts)) };

        let gctl = unsafe { gctl_ptr.read() };
        let intsts = unsafe { intsts_ptr.read() };

        serial_println!(
            "After RUN -> CTL=0x{:08X}, LPIB=0x{:X}, GCTL=0x{:08X}, INTSTS=0x{:08X}",
            ctl,
            lpib,
            gctl,
            intsts
        );

    
        // Poll LPIB to watch playback progress
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
