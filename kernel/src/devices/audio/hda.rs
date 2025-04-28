use crate::{
    debug_println, devices::{audio::{buffer::{setup_bdl, BdlEntry}, command_buffer::RirbBuffer, commands::{CorbEntry, HdaVerb, NodeParams}, wav_parser::load_wav}, mmio::MMioConstPtr, pci::{read_config, walk_pci_bus, DeviceInfo}}, events::{futures::devices::HWRegisterWrite, nanosleep_current_event}, interrupts::x2apic, memory::HHDM_OFFSET, serial_println
};

use crate::devices::{
    audio::hda_regs::HdaRegisters,
    mmio::MMioPtr,
};
use core::{ mem::offset_of, ptr::{read_volatile, write_volatile}};
use alloc::vec;
use alloc::vec::Vec;

use wavv::Data;
// use goblin::elf::reloc::R_AARCH64_TLSLE_LDST8_TPREL_LO12;
use x86_64::structures::idt::InterruptStackFrame;
// use crate::devices::audio::command_buffer::{CommandBuffer, WidgetAddr};
use crate::devices::audio::dma::DmaBuffer;


use super::{command_buffer::CorbBuffer, commands::RirbEntry, widget_info::WidgetInfo};

/// Physical BAR address (used during development before PCI scan)
/// TODO - need to find a betterr way so this variable doesnt exist
const HDA_BAR_PHYS: u32 = 0x81010000;
const DELAY_NS: u64 = 100_000;

pub struct AudioData {
    pub bytes: MMioConstPtr<u8>,
    pub len: usize,
    pub data: Data,
    pub fmt: u16
}

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
    pub virt_base: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub regs: &'static mut HdaRegisters,
    pub cmd_buf: Option<CorbBuffer>,
    pub rirb_buf: Option<RirbBuffer>,
}

impl IntelHDA {
    /// Initializes HDA controller:
    /// - Finds the PCI device
    /// - Maps BAR to virtual address (hhdm ofset + address)
    pub async fn init() -> Option<Self> {
        let device = find_hda_device()?;
        let bar = get_bar(&device)?;

        let virt = *HHDM_OFFSET + bar as u64;
        let regs = unsafe {&mut *(virt.as_u64() as *mut HdaRegisters)};

        debug_println!(
            "Intel HDA found: vendor=0x{:X}, device=0x{:X}, BAR=0x{:X} (virt: 0x{:X})",
            device.vendor_id,
            device.device_id,
            bar,
            virt
        );

        let mut hda = IntelHDA {
            base: bar,
            virt_base: virt.as_u64(),
            regs,
            vendor_id: device.vendor_id,
            device_id: device.device_id,
            cmd_buf: None,
            rirb_buf: None,
        };

        // reset the HDA
        debug_println!("resetting the hda");
        hda.reset().await;

        debug_println!("initializing the corb");
        hda.init_corb().await;

        debug_println!("initializing the rirb");
        hda.init_rirb().await;

        // enable interrupts
        let intctl_addr = (hda.virt_base + 0x20) as *mut u32;
        let intctl_val = ((1 << 31) | (1 << 4)) as u32; // TODO check the correct stream int is enabled, idk if 4 is the right num to shift by
        unsafe {
            let before = read_volatile(intctl_addr);
            serial_println!("INTCTL before write: 0x{:08X}", before);

            write_volatile(intctl_addr, intctl_val);

            let after = read_volatile(intctl_addr);
            serial_println!("INTCTL after write:  0x{:08X}", after);

            if (after & (1 << 31)) != 0 {
                serial_println!("Global interrupts are enabled.");
            } else {
                serial_println!("Global interrupts are not enabled.");
            }

            if (after & (1 << 4)) != 0 {
                serial_println!("Interrupt for stream 4 is enabled.");
            } else {
                serial_println!("Interrupt for stream 4 is not enabled.");
            }
        }
        
        // test we can play some audio
        hda.test_dma_transfer().await;
        
        Some(hda)
    } 

    /// Initializes the CORB
    pub async fn init_corb(&mut self) {
        // stop the CORB DMA engine
        let corbctl_addr = (self.virt_base + 0x4c) as *mut u8;
        // let mut corbctl_val = unsafe {read_volatile(corbctl_addr)};
        unsafe {
            write_volatile(corbctl_addr, 0);
        }
        
        // wait for the hw to acknowledge the write
        let mut corbctl_val = unsafe {read_volatile(corbctl_addr)};
        // TODO: fix this spin loop
        while (corbctl_val >> 1) & 1 != 0 {
            corbctl_val = unsafe {read_volatile(corbctl_addr)};
        }

        // Determine the size of the CORB
        let corbsize_addr = (self.virt_base + 0x4e) as *mut u8;
        let corb_size_reg = unsafe { read_volatile(corbsize_addr) };
        let corb_size: u16;
        let corb_size_val: u8;
        if (corb_size_reg >> 6) & 1 == 1 {
            corb_size = 256;
            corb_size_val = 2;
        } else if (corb_size_reg >> 5) & 1 == 1 {
            corb_size = 16;
            corb_size_val = 1;
        } else {
            corb_size = 2;
            corb_size_val = 0;
        }
        // now actually write the size
        debug_println!("setting the corb size");
        unsafe { write_volatile(corbsize_addr, corb_size_val); } // TODO: This line isnt actually needed since qemu only suports one size so remove maybe?

        // Allocate a buffer
        let corb_buf = DmaBuffer::new(4096).expect("Failed to alloc CORB");
        assert_eq!(corb_buf.virt_addr.as_u64() & (128 - 1), 0);
        let corb = CorbBuffer::new(&corb_buf, corb_size);
        self.cmd_buf = Some(corb); // TODO: why is this an option?

        // program the CORB base registers
        let corbbase = corb_buf.phys_addr.as_u64() & !(128 - 1);
        let corbbase_addr = (self.virt_base + 0x40) as *mut u32;
        debug_println!("writing the corb base addr");
        unsafe {
            write_volatile(corbbase_addr, (corbbase & 0xFFFFFFC0) as u32);
            write_volatile(corbbase_addr.add(1), ((corbbase >> 32) & 0xFFFFFFFF) as u32);
        }

        // TODO: might need to mess with the sizes that we are writing, we will see if qemu gets mad at us
        // reset the hw read pointer
        debug_println!("resetting the read pointer");
        let rp_addr = (self.virt_base + 0x4a) as *mut u16;
        unsafe { write_volatile(rp_addr, 1 << 15); }
    
        let mut rp_val = unsafe { read_volatile(rp_addr) };
        while rp_val >> 15 != 1 {
            rp_val = unsafe { read_volatile(rp_addr) };
        }

        unsafe { write_volatile(rp_addr, 0); }
        rp_val = unsafe { read_volatile(rp_addr) };
        // TODO: fix this spin loop
        while rp_val >> 15 != 0 {
            rp_val = unsafe { read_volatile(rp_addr) };
        }
        debug_println!("read pointer val: {:X}", rp_val);

        // set the write pointer to 0
        debug_println!("clear the write pointer reg");
        let wp_addr = (self.virt_base + 0x48) as *mut u8;
        unsafe { write_volatile(wp_addr, 0); }

        // set the run bit
        debug_println!("setting the run bit");
        unsafe { write_volatile(corbctl_addr, 2); } // TODO: figure out if this is needed or do we only set the run bit if there are commands to process?
        corbctl_val = unsafe { read_volatile(corbctl_addr) };
        // TODO: fix this spin loop
        while (corbctl_val >> 1) & 1 != 1 {
            corbctl_val = unsafe { read_volatile(corbctl_addr) };
        }
        debug_println!("finished initializing the corb");
        debug_println!();
    }

    /// initializes the RIRB
    pub async fn init_rirb(&mut self) {
        // stop the DMA engine
        let rirbctl_addr = (self.virt_base + 0x5c) as *mut u8;
        unsafe {
            write_volatile(rirbctl_addr, 0);
        }

        // wait for ack
        let mut ctl_val = unsafe { read_volatile(rirbctl_addr) };
        // TODO: fix this spin loop
        while (ctl_val >> 1) & 1 != 0 {
            ctl_val = unsafe { read_volatile(rirbctl_addr) };
        }

        // Determine the RIRB size
        let rirbsize_addr = (self.virt_base + 0x5e) as *mut u8;
        let rirbsize_val = unsafe { read_volatile(rirbsize_addr) };
        let rirb_size: u16;
        if (rirbsize_val >> 6) & 1 == 1 {
            rirb_size = 256;
        } else if (rirbsize_val >> 5) & 1 == 1 {
            rirb_size = 16;
        } else {
            rirb_size = 2;
        }

        // Allocate a buffer
        let rirb_buf = DmaBuffer::new(4096).expect("Failed to alloc CORB");
        assert_eq!(rirb_buf.virt_addr.as_u64() & (128 - 1), 0);
        let rirb = RirbBuffer::new(&rirb_buf, rirb_size);
        self.rirb_buf = Some(rirb);

        // program the RIRB base registers
        let rirbbase = rirb_buf.phys_addr.as_u64() & !(128 - 1);
        let rirbbase_addr = (self.virt_base + 0x50) as *mut u32;
        debug_println!("writing the rirb base addr");
        unsafe {
            write_volatile(rirbbase_addr, (rirbbase & 0xFFFFFFC0) as u32);
            write_volatile(rirbbase_addr.add(1), ((rirbbase >> 32) & 0xFFFFFFFF) as u32);
        }

        // reset the hw write pointer
        debug_println!("resetting the write pointer");
        let wp_addr = (self.virt_base + 0x58) as *mut u16;
        unsafe { write_volatile(wp_addr, 0); }
        // no need to check and wait like in corb cause this bit is always read a 0 for some reason

        // set interrupt count to half the size (it should accept 0 as 256 but it does not for some reason)
        let intcnt_addr = (self.virt_base + 0x5A) as *mut u16;
        unsafe { write_volatile(intcnt_addr, rirb_size / 2); }

        // set the run bit
        debug_println!("setting the run bit");
        unsafe { write_volatile(rirbctl_addr, 2); }
        ctl_val = unsafe { read_volatile(rirbctl_addr) };
        // TODO: fix this spin loop
        while (ctl_val >> 1) & 1 != 1 {
            ctl_val = unsafe { read_volatile(rirbctl_addr) };
        }
        debug_println!("finished initializing the rirb");
        debug_println!();
    }

    /// sends a command if the buffer is not full
    /// TODO: docs
    pub async fn send_command(&mut self, codec_address: u32, node_id: u32, command: HdaVerb, data: u16) -> Option<()> {
        let corb = self.cmd_buf.as_mut().unwrap();
        // first gotta check if the buffer is full
        // debug_println!("checking if the buffer is full");
        let corbrp_addr = (self.virt_base + 0x4A) as *mut u8;
        let corbrp_val = unsafe { read_volatile(corbrp_addr) };
        corb.set_read_idx(corbrp_val as u16);
        if corb.is_full() {
            debug_println!("buffer is full :(");
            return None
        }

        // debug_println!("sending a command to the corb");
        let cmd = CorbEntry::create_entry(codec_address, node_id, command, data);
        unsafe {
            corb.send(cmd).await;
            // next update the write pointer to indicate to hardware
            let wp_addr = (self.virt_base + 0x48) as *mut u8;
            write_volatile(wp_addr, (self.cmd_buf.as_ref().unwrap().get_write_idx() & 0xFF) as u8);
        }
        Some(())
    }

    /// receive a response from the RIRB
    /// TODO: docs
    pub async fn receive_response(&mut self) -> Option<RirbEntry> {
        // debug_println!("waiting for a response on the RIRB");
        let rirb = self.rirb_buf.as_mut().unwrap();
        let rirbwp_addr = (self.virt_base + 0x58) as *mut u16;
        let mut rirbwp_val = unsafe { read_volatile(rirbwp_addr) };
        rirb.set_write_idx(rirbwp_val);
        
        // TODO: figure out a better way to wait for a response (this is not very elegant)
        let mut counter = 100000;
        while rirb.is_empty() && counter > 0 {
            rirbwp_val = unsafe { read_volatile(rirbwp_addr) };
            rirb.set_write_idx(rirbwp_val);
            counter -= 1;
        }

        if counter == 0 {
            // timeout
            debug_println!("timed out while waiting");
            return None
        }

        unsafe { Some(rirb.read().await) }
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

    pub async fn probe_afg_and_widgets(&mut self) -> Vec<WidgetInfo> {
        debug_println!("probing afg and widgets");
        let mut widgets = Vec::new();
    
        self.send_command(0, 0, HdaVerb::GetParameter, NodeParams::NodeCount.as_u16())
            .await.expect("Failed to send GetParameter NodeCount");
    
        let fg_count_raw = self.receive_response().await
            .expect("Failed to receive NodeCount response")
            .get_response();
    
        let fg_count = fg_count_raw & 0xFF;
        debug_println!("Function group count: {}", fg_count);
    
        let mut afg_nid = None;
        for i in 1..=fg_count {
            self.send_command(0, i, HdaVerb::GetParameter, NodeParams::FunctionGroupType.as_u16())
                .await.expect("Failed to send GetParameter FunctionGroupType");
    
            let group_type = self.receive_response().await
                .expect("Failed to receive FunctionGroupType response")
                .get_response();
    
            debug_println!("Func group node {} type: 0x{:X}", i, group_type);
    
            if (group_type & 0xF) == 0x01 {
                afg_nid = Some(i as u8);
                break;
            }
        }
    
        let afg_node = match afg_nid {
            Some(nid) => nid,
            None => {
                debug_println!("No AFG found!");
                return widgets;
            }
        };
        debug_println!("AFG found at node {}", afg_node);
    
        self.send_command(0, afg_node as u32, HdaVerb::GetParameter, NodeParams::NodeCount.as_u16())
            .await.expect("Failed to send GetParameter NodeCount for AFG");
    
        let list_length = self.receive_response().await
            .expect("Failed to receive NodeCount for AFG");
        // list_length.print_response();
    
        let total_nodes = (list_length.get_response() & 0xFF) as u8;
        let start_id = ((list_length.get_response() >> 16) & 0xFF) as u8;
    
        if total_nodes == 0 {
            debug_println!("AFG {} has 0 subnodes — using brute-force widget scan", afg_node);
        } else {
            debug_println!(
                "AFG {} has {} subnodes starting at {}",
                afg_node,
                total_nodes,
                start_id
            );
        }
    
        for node in 0..total_nodes {
            let nid = start_id + node;
            debug_println!("node: {}", nid);
    
            self.send_command(0, nid as u32, HdaVerb::GetParameter, NodeParams::AudioWidgetCap.as_u16()).await.expect("Failed to send GetParameter AudioWidgetCap");
    
            let val = self.receive_response().await.expect("Failed to receive AudioWidgetCap");
            // val.print_response();
    
            let wtype = (val.get_response() >> 20) & 0xF;
    
            let mut w = WidgetInfo::new(nid);
            w.widget_type = wtype;

            self.send_command(0, nid as u32, HdaVerb::GetParameter, NodeParams::NodeCount.as_u16()).await.expect("nope");
            w.node_count = self.receive_response().await.expect("failed to get node count").get_response();
    
            self.send_command(0, nid as u32, HdaVerb::GetParameter, NodeParams::PinCap.as_u16()).await.expect("Failed to send GetParameter PinCap");
            w.pin_caps = self.receive_response().await.expect("Failed to receive PinCap").get_response();
    
            self.send_command(0, nid as u32, HdaVerb::GetParameter, NodeParams::InputAmplifierCap.as_u16()).await.expect("Failed to send GetAmpCapabilities");
            w.amp_in_caps = self.receive_response().await.expect("Failed to receive GetAmpCapabilities").get_response();
    
            self.send_command(0, nid as u32, HdaVerb::GetParameter, NodeParams::OutputAmplifierCap.as_u16()).await.expect("Failed to send GetAmpOutCaps");
            w.amp_out_caps = self.receive_response().await.expect("Failed to receive GetAmpOutCaps").get_response();
    
            self.send_command(0, nid as u32, HdaVerb::GetVolumeKnobCaps, 0).await.expect("Failed to send GetVolumeKnobCaps");
            w.volume_knob = self.receive_response().await.expect("Failed to receive GetVolumeKnobCaps").get_response();
    
            self.send_command(0, nid as u32, HdaVerb::GetConfigDefault, 0).await.expect("Failed to send GetConfigDefault");
            w.config_default = self.receive_response().await.expect("Failed to receive GetConfigDefault").get_response();
    
            self.send_command(0, nid as u32, HdaVerb::GetParameter, NodeParams::ConnectionListLength.as_u16()).await.expect("Failed to send GetParameter ConnectionListLength");
            let resp_val = self.receive_response().await.expect("Failed to receive ConnectionListLength").get_response();
    
            let conn_len = (resp_val & 0x7F) as u8;
    
            for i in 0..conn_len {
                self.send_command(0, nid as u32, HdaVerb::GetConnectionListEntry, i as u16).await.expect("Failed to send GetConnectionListEntry");
                let conn = (self.receive_response().await.expect("Failed to receive GetConnectionListEntry").get_response() & 0xFF) as u8;
    
                w.conn_list.push(conn);
            }
    
            debug_println!(
                "Discovered widget: NID={} type=0x{:X}, connections={:?}, node_count=0x{:X}",
                w.nid,
                w.widget_type,
                w.conn_list,
                w.node_count
            );
    
            widgets.push(w);
        }
    
        let nonzero_widgets: Vec<_> = widgets.iter().filter(|w| w.widget_type != 0).collect();
        if nonzero_widgets.is_empty() {
            debug_println!("All widgets returned 0 — codec likely not present or not initialized correctly.");
        }
    
        widgets
    }
    

    pub async fn trace_path_to_dac(&mut self, pin_node: u8) -> Option<(u8, u8)> {
        let mut stack: Vec<(u8, Vec<u8>)> = vec![(pin_node, vec![pin_node])];
    
        while let Some((node, path)) = stack.pop() {
            self.send_command(0, node as u32, HdaVerb::GetParameter, NodeParams::AudioWidgetCap.as_u16()).await.expect("Failed to send AudioWidgetCap");
            let widget_type = self.receive_response().await.expect("Failed to receive AudioWidgetCap").get_response();
            let wtype = (widget_type >> 20) & 0xF;
    
            debug_println!("trace: node {} has type 0x{:X}", node, wtype);
            if wtype == 0x0 {
                debug_println!("trace: found DAC at node {}", node);
                return Some((pin_node, node));
            }
    
            self.send_command(0, node as u32, HdaVerb::GetParameter, NodeParams::ConnectionListLength.as_u16()).await.expect("Failed to send ConnectionListLength");
            let conn_len_resp = self.receive_response().await.expect("Failed to receive ConnectionListLength").get_response();
            let conn_len = (conn_len_resp & 0x7F) as u8;
    
            for i in 0..conn_len {
                self.send_command(0, node as u32, HdaVerb::GetConnectionListEntry, i as u16).await.expect("Failed to send GetConnectionListEntry");
                let conn_resp = self.receive_response().await.expect("Failed to receive GetConnectionListEntry").get_response();
                let conn_node = (conn_resp & 0xFF) as u8;
    
                let mut new_path = path.clone();
                new_path.push(conn_node);
                stack.push((conn_node, new_path));
            }
        }
    
        debug_println!("trace: no path to DAC found");
        None
    }
        
    /// Resets the controller using GCTL register:
    /// - Clears and sets CRST bit (bit 0)
    pub async fn reset(&mut self) {
        unsafe {
            let gctl_ptr = MMioPtr((self.regs as *const _ as *const u8).add(offset_of!(HdaRegisters, gctl)) as *mut u32);
            let gctl = gctl_ptr.read();

            debug_println!("GCTL before clearing CRST: 0x{:X}", gctl_ptr.read());


            gctl_ptr.write(gctl & !(1 << 0));
            HWRegisterWrite::new(gctl_ptr.as_ptr(), 0x1, 0).await;

            let gctl = gctl_ptr.read();
            debug_println!("GCTL after clearing CRST:  0x{:X}", gctl);
            
            gctl_ptr.write(gctl | (1 << 0));
            debug_println!(
                "GCTL after setting CRST:   0x{:X}",
                 gctl_ptr.read()
            );

            HWRegisterWrite::new(gctl_ptr.as_ptr(), 0x1, 1).await;
            nanosleep_current_event(500_000).unwrap().await; // wait 0.5 ms


            debug_println!("CRST acknowledged by controller");

            // Delay 0.1 ms for codecs to get initialized (can we safely go smaller?)
            nanosleep_current_event(1_000_000).unwrap().await;


            let statests_ptr = (self.regs as *const _ as *const u8).add(offset_of!(HdaRegisters, statests)) as *const u16;
            let statests = core::ptr::read_volatile(statests_ptr);
            debug_println!("STATESTS (chheckking codec presence): 0x{:X}", statests);
        }
    }

    /// Enables pin widget output (sets EAPD bit in pin control)
    // pub async fn enable_pin(&mut self, node: u8) {
    //     let pin_cntl = unsafe {
    //         self.cmd_buf.as_mut().unwrap().cmd12(WidgetAddr(0, node), GetPinControl as u32, 0).await
    //     } | 0x40; // Set EAPD bit
    
    //     unsafe {
    //         self.cmd_buf.as_mut().unwrap().cmd12(WidgetAddr(0, node), SetPinControl as u32, (pin_cntl & 0xFF) as u8).await;
    //     }
    
    //     serial_println!("Pin widget control set for node {}", node);
    // }
    

    /// Sets stream/channel for node (verb 0x706)
    // pub async fn set_stream_channel(&mut self, node: u8, channel: u8) {
    //     unsafe {
    //         self.cmd_buf.as_mut().unwrap().cmd12(WidgetAddr(0, node), SetStreamChannel as u32, channel).await;
    //     }
    
    //     serial_println!("Stream channel set for node {}", node);
    // }
    

    /// Sets amplifier gain (extended verb 0x03)
    // pub async fn set_amplifier_gain(&mut self, node: u8, value: u16) {
    //     unsafe {
    //         self.cmd_buf.as_mut().unwrap().cmd4(WidgetAddr(0, node), SetAmplifierGain as u32, value).await;
    //     }
    
    //     serial_println!("Amplifier gain set for node {}", node);
    // }
    

    /// Sets converter format (extended verb 0x02)
    // pub async fn set_converter_format(&mut self, node: u8, fmt: u16) {
    //     unsafe {
    //         self.cmd_buf.as_mut().unwrap().cmd4(WidgetAddr(0, node), SetConverterFormat as u32, fmt).await;
    //     }
    
    //     serial_println!("Converter format set for node {}", node);
    // }
    

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

    pub async fn test_dma_transfer(&mut self) {
        // turn on the nodes
        self.send_command(0, 0, HdaVerb::SetPowerState, 0).await.expect("Failed to send command to the CORB");
        let mut response = self.receive_response().await.expect("Failed to receive response from the RIRB");
        // response.print_response();
        
        // do the get param thingy
        self.send_command(0, 0, HdaVerb::GetParameter, NodeParams::NodeCount.as_u16()).await.expect("Failed to send command to the CORB");
        response = self.receive_response().await.expect("Failed to receive response from the RIRB");
        // response.print_response();

        let audio_data = load_wav().await.expect("Wav error");

        let widget_list = self.probe_afg_and_widgets().await;
        debug_println!("Total widgets discovered: {}", widget_list.len());

        debug_println!("___________TRACE_____________");
        if let Some((pin_node, dac_node)) = self.trace_path_to_dac(3).await {
            debug_println!("Traced path from pin {} to DAC {}", pin_node, dac_node);
        
            self.send_command(0, dac_node as u32, HdaVerb::SetPowerState, 0x00).await.expect("Failed to send SetPowerState to DAC");
            self.receive_response().await.expect("No response to SetPowerState");
        
            // 0x10 means strream number 1, channel 0
            self.send_command(0, dac_node as u32, HdaVerb::SetStreamChannel, 0x10).await.expect("Failed to send SetStreamChannel");
            self.receive_response().await.expect("No response to SetStreamChannel");
        
            // Set ampplifier gain on the DAC: unmuted, 0 dB gain
            // 0xB035 enabbles output for both channels with default ggain
            self.send_command(0, dac_node as u32, HdaVerb::SetAmplifierGain, 0xB035).await.expect("Failed to send SetAmplifierGain");
            self.receive_response().await.expect("No response to SetAmplifierGain");
        
            // Configure the DAC format to 48kHz, 16-bit, stereoo
            self.send_command(0, dac_node as u32, HdaVerb::SetConverterFormat, audio_data.fmt).await.expect("Failed to send SetConverterFormat");
            self.receive_response().await.expect("No response to SetConverterFormat");
        
            // Read current pin conttrol to preserve existing bitts before setting EAPD/output
            self.send_command(0, pin_node as u32, HdaVerb::GetPinControl, 0).await.expect("Failed to send GetPinControl");
            let mut pin_ctrl = self.receive_response().await.expect("No response to GetPinControl").get_response();
        
            // Enable output and EAPD by setting bbbits 6 and 7 (0xC0)
            // Idk if this actually does anything, it does not look like qemu actually changes any values?
            pin_ctrl |= 0xC0;
            self.send_command(0, pin_node as u32, HdaVerb::SetPinControl, (pin_ctrl & 0xFF) as u16).await.expect("Failed to send SetPinControl");
            self.receive_response().await.expect("No response to SetPinControl");

            // self.send_command(0, pin_node as u32, HdaVerb::GetEAPDBTLEnable, 0).await.expect("failed");
            // let temp = self.receive_response().await.expect("no response to geteapdbtl cmd");
            // temp.print_response();

            debug_println!("Playback path [Pin {} → DAC {}] configured successfully.", pin_node, dac_node);
        } else {
            debug_println!("Could not trace a valid path from pin to DAC.");
        }
        
        
        
        // create BDL stuff
        
        debug_println!("starting to alloc BDL");
        let audio_buf = DmaBuffer::new(audio_data.len/3).expect("Failed to allocate audio buffer");
        let bdl_buf = DmaBuffer::new(core::mem::size_of::<BdlEntry>() * 32).expect("Failed BDL");
        assert_eq!(bdl_buf.phys_addr.as_u64() % 128, 0, "BDL not 128-byte aligned");
        
        debug_println!("audio data len: {}", audio_data.len);
        debug_println!("audio buf size: {}", audio_buf.size);

        debug_println!("audio_data.bytes.asptr 0x{:X}", audio_data.bytes.as_ptr() as u64);
        debug_println!("audio bug virt addrress 0x{:X}", audio_buf.virt_addr.as_mut_ptr::<u8>() as u64);
        unsafe {
            core::ptr::copy_nonoverlapping(
                audio_data.bytes.as_ptr(), 
                audio_buf.virt_addr.as_mut_ptr::<u8>(), 
                audio_data.len/3);
        }
        // assert!(false);

        //old code back
        // let audio_buf = DmaBuffer::new(64 * 1024).expect("Failed to allocate audio buffer");
        // let bdl_buf = DmaBuffer::new(core::mem::size_of::<BdlEntry>() * 32).expect("Failed BDL");
        // assert_eq!(bdl_buf.phys_addr.as_u64() % 128, 0, "BDL not 128-byte aligned");
    
        // for i in 0..audio_buf.size {
        //     unsafe {
        //         *audio_buf.virt_addr.as_mut_ptr::<u8>().add(i) =
        //             if i % 3 == 0 { 0x00 } else if i % 3 == 1 { 0x10 } else { 0xFF };
        //     }
        // }
        
        debug_println!("before bdl setup");
        let bdl_ptr = bdl_buf.as_ptr::<BdlEntry>();
        let num_entries = setup_bdl(
            bdl_ptr,
            audio_buf.phys_addr.as_u64(),
            audio_buf.size as u32,
            0x1000,
        );
    
        debug_println!("setup_bdl returned {} entries", num_entries);
        
        // Flush cache to ensure BDL/Audio in RAM for DMA
        unsafe { core::arch::asm!("wbinvd"); }

        for i in 0..16 {
            let b = unsafe { *(audio_buf.virt_addr.as_u64() as *const u8).add(i) };
            debug_println!("Audio buf[{}] = {:02X}", i, b);
        }

        // begin configuring stream desc
        let stream_base = self.virt_base + 0x80 + 4 * 0x20;
        // first make sure that the stream is stopped and then reset it
        let ctl0_addr = stream_base as *mut u8;
        let mut ctl0_val = unsafe { read_volatile(ctl0_addr) };
        unsafe {
            write_volatile(ctl0_addr, ctl0_val & !(1 << 1));
            ctl0_val = read_volatile(ctl0_addr);
            write_volatile(ctl0_addr, ctl0_val | 1);
            ctl0_val = read_volatile(ctl0_addr);
        }

        // wait for hw to ack
        while ctl0_val & 1 != 1 {
            ctl0_val = unsafe {
                read_volatile(ctl0_addr)
            };
        }
        // now clear SRST
        unsafe {
            write_volatile(ctl0_addr, ctl0_val & !1);
            ctl0_val = read_volatile(ctl0_addr);
        }
        while ctl0_val & 1 != 0 {
            ctl0_val = unsafe {
                read_volatile(ctl0_addr)
            };
        }

        // write bdl address
        let bdladr_addr = (stream_base + 0x18) as *mut u64;
        let bdladr_val: u64;
        unsafe {
            write_volatile(bdladr_addr, bdl_buf.phys_addr.as_u64());
            bdladr_val = read_volatile(bdladr_addr);
        }
        debug_println!("address: {:X}", bdladr_val);

        let cbl_addr = (stream_base + 0x8) as *mut u32;
        let cbl_val: u32;
        unsafe {
            write_volatile(cbl_addr, audio_buf.size as u32);
            cbl_val = read_volatile(cbl_addr);
        }
        debug_println!("cbl: {:X}", cbl_val);

        // write the LVI
        let lvi_addr = (stream_base + 0xC) as *mut u16;
        unsafe {write_volatile(lvi_addr, num_entries as u16 - 1);}

        // now lets congifure the fmt reg
        let fmt_addr = (stream_base + 0x12) as *mut u16;
        let fmt_write = audio_data.fmt; // 8 bits per sample
        let fmt_val: u16;
        unsafe {
            write_volatile(fmt_addr, fmt_write);
            fmt_val = read_volatile(fmt_addr);
        }
        debug_println!("fmt_val: {:X}", fmt_val);

        let ctl2_addr = (stream_base + 2) as *mut u8;
        unsafe {write_volatile(ctl2_addr, 1 << 4);}
        let ctl2_val = unsafe {read_volatile(ctl2_addr)};
        debug_println!("ctl2: {:X}", ctl2_val);

        // now set the run bit and hope that the thing works (gonna set some interrupt bits as well)
        unsafe {
            write_volatile(ctl0_addr, 0x6);
        }
        
        for _ in 0..10 {
            unsafe{
                debug_println!("lpib: {}", read_volatile((stream_base + 0x4) as *const u32));
            }
            nanosleep_current_event(1_000_000_000).unwrap().await;
        }
    }
    
    
    
}

/// Walk PCI bus to find device with Class 0x04, Subclass 0x03 (FOUND FROM OSDEV)
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
