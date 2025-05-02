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
use x86_64::structures::idt::InterruptStackFrame;
use crate::devices::audio::dma::DmaBuffer;


use super::{command_buffer::CorbBuffer, commands::RirbEntry, widget_info::WidgetInfo};

/// Physical BAR address (used during development before PCI scan)
/// TODO - need to find a betterr way so this variable doesnt exist
const HDA_BAR_PHYS: u32 = 0x81010000;

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
    //// Initializes the Intel HDA controller.
    ///
    /// Steps:
    /// - Locates the HDA-compatible PCI device (Class 0x04, Subclass 0x03).
    /// - Maps the controller registers into virtual memory.
    /// - Resets the HDA controller via `reset()`.
    /// - Initializes CORB and RIRB buffers.
    /// - Enables interrupt delivery.
    pub async fn init() -> Option<Self> {
        let device = find_hda_device()?;
        let bar = get_bar(&device)?;

        let virt = *HHDM_OFFSET + bar as u64;
        let regs = unsafe {&mut *(virt.as_u64() as *mut HdaRegisters)};

        // Just gonna keep this one
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
        hda.reset().await;

        hda.init_corb().await;

        hda.init_rirb().await;

        // enable interrupts
        let intctl_addr = (hda.virt_base + 0x20) as *mut u32;
        let intctl_val = ((1 << 31) | (1 << 4)) as u32;
        unsafe {
            write_volatile(intctl_addr, intctl_val);
        }
        
        // test we can play some audio
        hda.test_dma_transfer().await;
        
        Some(hda)
    } 

    /// Initializes the CORB
    /// Steps:
    /// - Stops the CORB DMA engine and waits for the confirmation
    /// - Selects and configures the CORB size
    /// - Allocates a DMA bufferr and sets base address reegisterrs
    /// - Resets thehardwarer rerad/write pointerrs
    /// - Starts theCORB engines.
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
        unsafe { write_volatile(corbsize_addr, corb_size_val); } // TODO: This line isnt actually needed since qemu only suports one size so remove maybe?

        // Allocate a buffer
        let corb_buf = DmaBuffer::new(4096).expect("Failed to alloc CORB");
        assert_eq!(corb_buf.virt_addr.as_u64() & (128 - 1), 0);
        let corb = CorbBuffer::new(&corb_buf, corb_size);
        self.cmd_buf = Some(corb); // TODO: why is this an option?

        // program the CORB base registers
        let corbbase = corb_buf.phys_addr.as_u64() & !(128 - 1);
        let corbbase_addr = (self.virt_base + 0x40) as *mut u32;
        unsafe {
            write_volatile(corbbase_addr, (corbbase & 0xFFFFFFC0) as u32);
            write_volatile(corbbase_addr.add(1), ((corbbase >> 32) & 0xFFFFFFFF) as u32);
        }

        // reset the hw read pointer
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

        // set the write pointer to 0
        let wp_addr = (self.virt_base + 0x48) as *mut u8;
        unsafe { write_volatile(wp_addr, 0); }

        // set the run bit
        unsafe { write_volatile(corbctl_addr, 2); } // TODO: figure out if this is needed or do we only set the run bit if there are commands to process?
        corbctl_val = unsafe { read_volatile(corbctl_addr) };
        // TODO: fix this spin loop
        while (corbctl_val >> 1) & 1 != 1 {
            corbctl_val = unsafe { read_volatile(corbctl_addr) };
        }
    }

    /// initializes the RIRB
    /// Steps:
    /// - Disables the RIRB DMA engine
    /// - Deterrmines supported RIRB size and allocates buffer
    /// - Sets RIRB baseaddressregisterrs and configures interrupt count
    /// - Starts the RIRB engine
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
        unsafe {
            write_volatile(rirbbase_addr, (rirbbase & 0xFFFFFFC0) as u32);
            write_volatile(rirbbase_addr.add(1), ((rirbbase >> 32) & 0xFFFFFFFF) as u32);
        }

        // reset the hw write pointer
        let wp_addr = (self.virt_base + 0x58) as *mut u16;
        unsafe { write_volatile(wp_addr, 0); }
        // no need to check and wait like in corb cause this bit is always read a 0 for some reason

        // set interrupt count to half the size (it should accept 0 as 256 but it does not for some reason)
        let intcnt_addr = (self.virt_base + 0x5A) as *mut u16;
        unsafe { write_volatile(intcnt_addr, rirb_size / 2); }

        // set the run bit
        unsafe { write_volatile(rirbctl_addr, 2); }
        ctl_val = unsafe { read_volatile(rirbctl_addr) };
        // TODO: fix this spin loop
        while (ctl_val >> 1) & 1 != 1 {
            ctl_val = unsafe { read_volatile(rirbctl_addr) };
        }
    }

    /// sends a command if the buffer is not full
    /// 
    /// # Arguments
    /// * `codec_address`: ID of the codec on the HDA link
    /// * `node_id`: NID of the codec node to target
    /// * `command`: The verb of the opcode (e.g GetParameter, SetStream, etc)
    /// * `data`: Additional data or sub-verb argument
    /// 
    /// # Returns
    /// `None` if the CORB is full and sending the command failed, otherwise retuns `Some(())`
    pub async fn send_command(&mut self, codec_address: u32, node_id: u32, command: HdaVerb, data: u16) -> Option<()> {
        let corb = self.cmd_buf.as_mut().unwrap();
        // first check if the buffer is full
        let corbrp_addr = (self.virt_base + 0x4A) as *mut u8;
        let corbrp_val = unsafe { read_volatile(corbrp_addr) };
        corb.set_read_idx(corbrp_val as u16);
        if corb.is_full() {
            return None
        }

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
    /// 
    /// # Returns
    /// the next available `RirbEntry` if present and `None` if a timeout occurs
    pub async fn receive_response(&mut self) -> Option<RirbEntry> {
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

    /// Probes the audio function group and its widgets
    /// - Identifies the AFG node in thecodec
    /// - Queries its child nodes and their widget types and capabilities.
    /// - Populates a list of WidgetInffo structswith
    ///      - Widget type
    ///      - Connection List
    ///      - Amplifier capabipities
    ///      - Pin configurations
    ///      - Default configuration and volume controle
    /// 
    /// # Returns
    /// a vector of `WidgetInfo` representing the widget topology
    pub async fn probe_afg_and_widgets(&mut self) -> Vec<WidgetInfo> {
        let mut widgets = Vec::new();
    
        self.send_command(0, 0, HdaVerb::GetParameter, NodeParams::NodeCount.as_u16())
            .await.expect("Failed to send GetParameter NodeCount");
    
        let fg_count_raw = self.receive_response().await
            .expect("Failed to receive NodeCount response")
            .get_response();
    
        let fg_count = fg_count_raw & 0xFF;
    
        let mut afg_nid = None;
        for i in 1..=fg_count {
            self.send_command(0, i, HdaVerb::GetParameter, NodeParams::FunctionGroupType.as_u16())
                .await.expect("Failed to send GetParameter FunctionGroupType");
    
            let group_type = self.receive_response().await
                .expect("Failed to receive FunctionGroupType response")
                .get_response();
    
            if (group_type & 0xF) == 0x01 {
                afg_nid = Some(i as u8);
                break;
            }
        }
    
        let afg_node = match afg_nid {
            Some(nid) => nid,
            None => {
                return widgets;
            }
        };
    
        self.send_command(0, afg_node as u32, HdaVerb::GetParameter, NodeParams::NodeCount.as_u16())
            .await.expect("Failed to send GetParameter NodeCount for AFG");
    
        let list_length = self.receive_response().await
            .expect("Failed to receive NodeCount for AFG");
    
        let total_nodes = (list_length.get_response() & 0xFF) as u8;
        let start_id = ((list_length.get_response() >> 16) & 0xFF) as u8;
    
        for node in 0..total_nodes {
            let nid = start_id + node;
    
            self.send_command(0, nid as u32, HdaVerb::GetParameter, NodeParams::AudioWidgetCap.as_u16()).await.expect("Failed to send GetParameter AudioWidgetCap");
    
            let val = self.receive_response().await.expect("Failed to receive AudioWidgetCap");
    
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
    
            widgets.push(w);
        }
    
        widgets
    }
    
    /// Recursively traces a valid signal path from a pin node to a DAC node.
    /// 
    /// # Arguments
    /// - `pin_node`: Node ID of the output pin.
    /// 
    /// # Returns:
    /// - `Some((pin_node, dac_node))` if a DAC is found along the connection path.
    /// - `None` if no DAC is reachable.
    pub async fn trace_path_to_dac(&mut self, pin_node: u8) -> Option<(u8, u8)> {
        let mut stack: Vec<(u8, Vec<u8>)> = vec![(pin_node, vec![pin_node])];
    
        while let Some((node, path)) = stack.pop() {
            self.send_command(0, node as u32, HdaVerb::GetParameter, NodeParams::AudioWidgetCap.as_u16()).await.expect("Failed to send AudioWidgetCap");
            let widget_type = self.receive_response().await.expect("Failed to receive AudioWidgetCap").get_response();
            let wtype = (widget_type >> 20) & 0xF;
    
            if wtype == 0x0 {
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
    
        None
    }
        
    /// Resets the controller using GCTL register:
    /// - Clears and sets CRST bit (bit 0)
    pub async fn reset(&mut self) {
        unsafe {
            let gctl_ptr = MMioPtr((self.regs as *const _ as *const u8).add(offset_of!(HdaRegisters, gctl)) as *mut u32);
            let gctl = gctl_ptr.read();

            gctl_ptr.write(gctl & !(1 << 0));
            HWRegisterWrite::new(gctl_ptr.as_ptr(), 0x1, 0).await;

            let gctl = gctl_ptr.read();
            
            gctl_ptr.write(gctl | (1 << 0));

            HWRegisterWrite::new(gctl_ptr.as_ptr(), 0x1, 1).await;
            nanosleep_current_event(500_000).unwrap().await; // wait 0.5 ms

            // Delay 0.1 ms for codecs to get initialized (can we safely go smaller?)
            nanosleep_current_event(1_000_000).unwrap().await;
        }
    }

    /// Starts audio stream (sets RUN bit in SDxCTL)
    pub fn start_stream(&mut self, stream_idx: usize) {
        unsafe {
            let ctl = &mut self.regs.stream_regs[stream_idx].ctl0;
            write_volatile(ctl, read_volatile(ctl) | (1 << 1)); // RUN RUN RUN PLZ
        }
    }

    /// Stops audio stream (clears RUN bit in SDxCTL)
    pub fn stop_stream(&mut self, stream_idx: usize) {
        unsafe {
            let ctl = &mut self.regs.stream_regs[stream_idx].ctl0;
            write_volatile(ctl, read_volatile(ctl) & !(1 << 1)); // RUN STOPPPP
        }
    }

    /// Plays a WAV file throughh the audio output usning DMA.
    /// Steps:
    /// - Powers up codecs and discovers the pin-to-DAC signal path
    /// - Sends configuration verbs
    /// - Allocates and sets up BDLs for streaming audio chunks
    /// - Initializes the stream descriptor with control info
    /// - ALterrnates between the BDLs based on the IOC bit
    /// - 
    pub async fn test_dma_transfer(&mut self) {
        // turn on the nodes
        self.send_command(0, 0, HdaVerb::SetPowerState, 0).await.expect("Failed to send command to the CORB");
        self.receive_response().await.expect("Failed to receive response from the RIRB");
        
        self.send_command(0, 0, HdaVerb::GetParameter, NodeParams::NodeCount.as_u16()).await.expect("Failed to send command to the CORB");
        self.receive_response().await.expect("Failed to receive response from the RIRB");

        let audio_data = load_wav().await.expect("Wav error");

        self.probe_afg_and_widgets().await;

        if let Some((pin_node, dac_node)) = self.trace_path_to_dac(3).await {
        
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
            pin_ctrl |= 0xC0;
            self.send_command(0, pin_node as u32, HdaVerb::SetPinControl, (pin_ctrl & 0xFF) as u16).await.expect("Failed to send SetPinControl");
            self.receive_response().await.expect("No response to SetPinControl");
        } else {
            debug_println!("Could not trace a valid path from pin to DAC.");
        }
        
        // create BDL stuff
        let audio_buf = DmaBuffer::new(audio_data.len).expect("Failed to allocate audio buffer");
        let bdl_buf1 = DmaBuffer::new(core::mem::size_of::<BdlEntry>() * 16).expect("Failed BDL");
        let bdl_buf2 = DmaBuffer::new(core::mem::size_of::<BdlEntry>() * 16).expect("Failed BDL");

        assert_eq!(bdl_buf1.phys_addr.as_u64() % 128, 0, "BDL 1 not 128-byte aligned");
        assert_eq!(bdl_buf2.phys_addr.as_u64() % 128, 0, "BDL 2 not 128-byte aligned");
        
        unsafe {
            core::ptr::copy_nonoverlapping(
                audio_data.bytes.as_ptr(), 
                audio_buf.virt_addr.as_mut_ptr::<u8>(), 
                audio_data.len);
        }

        let mut last_byte_written = audio_buf.clone(); // tbh this probably does not need to exist but it is wtv atp

        let bdl_ptr_1 = bdl_buf1.as_ptr::<BdlEntry>();
        let mut num_entries = setup_bdl(
            bdl_ptr_1,
            last_byte_written.phys_addr.as_u64(),
            last_byte_written.size as u32,
            0x1000,
        );
        let num_entries_1 = num_entries;
        
        let mut num_bytes_bdl = (num_entries * 0x1000) as u32;
        
        last_byte_written.offset(num_bytes_bdl as u64);
        
        let bdl_ptr_2 = bdl_buf2.as_ptr::<BdlEntry>();
        num_entries = setup_bdl(
            bdl_ptr_2,
            last_byte_written.phys_addr.as_u64(),
            last_byte_written.size as u32,
            0x1000,
        );

        last_byte_written.offset((num_entries * 0x1000) as u64);
        
        
        // begin configuring stream desc
        let stream_base = self.virt_base + 0x80 + 4 * 0x20;
        
        // Flush cache to ensure BDL/Audio in RAM for DMA
        unsafe { core::arch::asm!("wbinvd"); }
        
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
        
        // lettuce clear our status bits
        let sdsts_addr = (stream_base + 0x3) as *const u8;
        
        unsafe {
            write_volatile(sdsts_addr.cast_mut(), 0x1C);
        }
        
        // write bdl address
        let bdladr_addr = (stream_base + 0x18) as *mut u64;
        unsafe {
            write_volatile(bdladr_addr, bdl_buf1.phys_addr.as_u64());
        }

        // write the cbl
        let cbl_addr = (stream_base + 0x8) as *mut u32;
        unsafe {
            write_volatile(cbl_addr, num_bytes_bdl);
        }

        // write the LVI
        let lvi_addr = (stream_base + 0xC) as *mut u16;
        unsafe {write_volatile(lvi_addr, num_entries_1 as u16 - 1);}

        // now lets congifure the fmt reg
        let fmt_addr = (stream_base + 0x12) as *mut u16;
        let fmt_write = audio_data.fmt; // 8 bits per sample
        unsafe {
            write_volatile(fmt_addr, fmt_write);
        }

        // set the stream num
        let ctl2_addr = (stream_base + 2) as *mut u8;
        unsafe { write_volatile(ctl2_addr, 1 << 4); }

        // now set the run bit and hope that the thing works (gonna set some interrupt bits as well)
        unsafe {
            write_volatile(ctl0_addr, 0x2);
        }

        let mut sts = unsafe { read_volatile((stream_base + 0x3) as *const u8) };
        let mut flag = true;
        let mut counter = 0;
        while (sts >> 2) & 1 != 1 {
            unsafe{
                // check for an IOC
                sts = read_volatile((stream_base + 0x3) as *const u8);

                if (sts >> 2) & 1 == 1 {
                    // stop stream
                    write_volatile(stream_base as *mut u8, 0x0);

                    if flag {
                        // clear sts
                        write_volatile((stream_base + 0x3) as *mut u8, 0x40);
                        sts = read_volatile((stream_base + 0x3) as *const u8);
    
                        // update cbl
                        num_bytes_bdl = 0x1000 * num_entries as u32;
                        write_volatile((stream_base + 0x8) as *mut u32, num_bytes_bdl);
    
                        // update lvi
                        write_volatile((stream_base + 0xC) as *mut u16, num_entries as u16 - 1);
    
                        // update bdl ptr
                        if counter % 2 == 0 {
                            write_volatile((stream_base + 0x18) as *mut u64, bdl_buf2.phys_addr.as_u64());
                        } else {
                            write_volatile((stream_base + 0x18) as *mut u64, bdl_buf1.phys_addr.as_u64());
                        }
                        
                        // start stream
                        write_volatile(stream_base as *mut u8, 0x2);
                        
                        // now we gotta load up the next buffer
                        if counter % 2 == 0 {
                            // load up buf1
                            num_entries = setup_bdl(
                                bdl_ptr_1,
                                last_byte_written.phys_addr.as_u64(),
                                last_byte_written.size as u32,
                                0x1000,
                            );
                        } else {
                            // load up buf2
                            num_entries = setup_bdl(
                                bdl_ptr_1,
                                last_byte_written.phys_addr.as_u64(),
                                last_byte_written.size as u32,
                                0x1000,
                            );
                        }

                        // move the copy of the audio data
                        num_bytes_bdl = (num_entries * 0x1000) as u32;
        
                        last_byte_written.offset(num_bytes_bdl as u64);

                        if last_byte_written.size == 0 {
                            flag = false;
                        }
                        counter += 1;
                    }
                }
            }
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
