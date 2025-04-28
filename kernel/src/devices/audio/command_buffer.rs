use core::ptr::{read_volatile, write_volatile};
use crate::{debug_println, devices::audio::dma::DmaBuffer, events::nanosleep_current_event, serial_println};

use super::commands::{CorbEntry, RirbEntry};

const CORBRUN: u8 = 1 << 1;
// const CORBRPRST: u16 = 1 << 15;
const RIRBDMAEN: u8 = 1 << 1;
const RINTCTL: u8 = 1 << 0;
const RIRBWPRST: u16 = 1 << 15;
const ICB: u16 = 1 << 0;
const IRV: u16 = 1 << 1;

#[derive(Copy, Clone)]
pub struct WidgetAddr(pub u8, pub u8);

/// A struct for operating the CORB
pub struct CorbBuffer {
    /// The virtual base address of the CORB
    pub base: u64,
    /// The physical base address of the CORB
    pub phys_base: u64,
    /// The next block to be written to. It is an index
    pub write_idx: u16,
    /// The next block to read from, only hear to see when the CORB is full.
    pub read_idx: u16,
    /// Then number of entries that are in this CORB
    pub size: u16,
}

unsafe impl Send for CorbBuffer {}
unsafe impl Sync for CorbBuffer {}

impl CorbBuffer {
    /// Initializes a new CORB
    /// 
    /// # Arguments
    /// * `base`: a DmaBuffer object that points to the memory that the CORB is on
    /// * `size`: The number of entries that are contained in this CORB
    /// 
    /// # Returns
    /// `self`
    pub fn new(base: &DmaBuffer, size: u16) -> Self {
        // debug_println!("creating a CORB with {} entries", size);
        Self {
            base: base.virt_addr.as_u64(),
            phys_base: base.phys_addr.as_u64(),
            write_idx: 0,
            read_idx: 0,
            size,
        }
    }

    /// Returns the index of the last written command
    pub fn get_write_idx(&self) -> u16 {
        self.write_idx
    }

    /// Returns the index of the last read command from the hardware
    pub fn get_read_idx(&self) -> u16 {
        self.read_idx
    }

    /// Sets the read idx to `idx`
    pub fn set_read_idx(&mut self, idx: u16) {
        self.read_idx = idx;
    }

    /// Checks to see if the CORB is full
    /// 
    /// # Returns
    /// * `true` if `write_idx + 1 == read_idx`
    /// * `false` otherwise 
    pub fn is_full(&self) -> bool {
        let mut next_write = self.write_idx + 1;
        if next_write == self.size {
            next_write = 0;
        }
        next_write == self.read_idx
    }

    /// Sends a cmd onto the CORB and increments the write index
    /// 
    /// # Arguments
    /// * `cmd`: the command to be written onto the CORB
    /// 
    /// # Safety
    /// This function preforms a raw pointer write to write the command to the CORB. This function assumes that the CORB is not full.
    pub async unsafe fn send(&mut self, cmd: CorbEntry) {
        assert!(!self.is_full());
        let mut next_write = self.write_idx + 1;
        if next_write == self.size {
            next_write = 0;
        }
        // debug_println!("next index to write to: {}", next_write);

        let write_address = (self.base + next_write as u64 * 4) as *mut CorbEntry;
        // debug_println!("the address to write to: 0x{:X}", write_address as u64);
        write_volatile(write_address, cmd);
        debug_println!("wrote cmd: 0x{:X}", cmd.get_cmd());

        self.write_idx = next_write;
        // debug_println!("set the write_idx to {}", self.write_idx);
    }
}

/// A struct for operating the RIRB
pub struct RirbBuffer {
    /// The virtual base address of the RIRB
    pub base: u64,
    /// The physical base address of the RIRB
    pub phys_base: u64,
    /// The next block to be written to
    pub write_idx: u16,
    /// The next block to read from
    pub read_idx: u16,
    /// Then number of entries that are in this RIRB
    pub size: u16,
}

unsafe impl Send for RirbBuffer {}
unsafe impl Sync for RirbBuffer {}

impl RirbBuffer {
    /// Initializes a new RIRB
    /// 
    /// # Arguments
    /// * `base`: a DmaBuffer object that points to the memory that the RIRB is on
    /// * `size`: The number of entries that are contained in this RIRB
    /// 
    /// # Returns
    /// `self`
    pub fn new(base: &DmaBuffer, size: u16) -> Self {
        debug_println!("creating a RIRB with {} entries", size);
        Self {
            base: base.virt_addr.as_u64(),
            phys_base: base.phys_addr.as_u64(),
            write_idx: 0,
            read_idx: 0,
            size,
        }
    }

    /// Returns the current read index
    pub fn get_read_idx(&self) -> u16 {
        self.read_idx
    }

    /// Sets the read index
    pub fn set_read_idx(&mut self, idx: u16) {
        self.read_idx = idx;
    }

    /// sets the index of the last written command
    pub fn set_write_idx(&mut self, idx: u16) {
        self.write_idx = idx;
    }

    /// Checks to see if the RIRB is empty
    /// 
    /// # Returns
    /// * `true` if `write_idx == read_idx`
    /// * `false` otherwise
    pub fn is_empty(&self) -> bool {
        self.write_idx == self.read_idx
    }

    /// Reads the next response from the RIRB and increments the read index
    /// 
    /// # Returns
    /// Returns the 8 byte response that is on the RIRB
    /// 
    /// # Safety
    /// This function preforms a raw pointer read to read from the RIRB. This function assumes that the RIRB is not empty.
    pub async unsafe fn read(&mut self) -> RirbEntry {
        assert!(!self.is_empty());
        let next_idx = (self.read_idx + 1) % self.size;
        // debug_println!("next index to read from: {}", next_idx);

        let read_addr = (self.base + (next_idx as u64 * 8)) as *mut RirbEntry;
        // debug_println!("the address to read from: 0x{:X}", read_addr as u64);
        let response = read_volatile(read_addr);
        // debug_println!("read response: 0x{:X} and resp_ex: {:X}", response.get_response(), response.get_response_ex());

        self.read_idx = next_idx;
        // debug_println!("set the read_idx to {}", self.read_idx);
        response
    }


    
}

pub struct CommandBuffer {
    pub base: usize,
    pub corb_virt: *mut u32,
    pub corb_phys: u64,
    pub corb_wp: *mut u16,
    pub corb_rp: *mut u16,
    pub corb_ctl: *mut u8,
    pub corb_size: *mut u8,
    pub corb_addr_l: *mut u32,
    pub corb_addr_h: *mut u32,
    pub corb_count: usize,

    pub rirb_virt: *mut u64,
    pub rirb_phys: u64,
    pub rirb_wp: *mut u16,
    pub rirb_ctl: *mut u8,
    pub rirb_size: *mut u8,
    pub rirb_addr_l: *mut u32,
    pub rirb_addr_h: *mut u32,
    pub rirb_count: usize,
    pub rirb_rp_shadow: u16,

    pub icoi: *mut u32,
    pub irii: *mut u32,
    pub ics: *mut u16,

    pub use_immediate: bool,
}

unsafe impl Send for CommandBuffer {}
unsafe impl Sync for CommandBuffer {}

impl CommandBuffer {
    pub async unsafe fn new(base: usize, corb_buf: &DmaBuffer, rirb_buf: &DmaBuffer) -> Self {
        // let base = (HHDM_OFFSET.as_u64() + base as u64) as usize;

        Self {
            base: base,
            corb_virt: corb_buf.virt_addr.as_mut_ptr() as *mut u32,
            corb_phys: corb_buf.phys_addr.as_u64(),
            corb_wp: (base + 0x48) as *mut u16,
            corb_rp: (base + 0x4A) as *mut u16,
            corb_ctl: (base + 0x4C) as *mut u8,
            corb_size: (base + 0x4E) as *mut u8,
            corb_addr_l: (base + 0x40) as *mut u32,
            corb_addr_h: (base + 0x44) as *mut u32,
            corb_count: 256,

            rirb_virt: rirb_buf.virt_addr.as_mut_ptr() as *mut u64,
            rirb_phys: rirb_buf.phys_addr.as_u64(),
            rirb_wp: (base + 0x58) as *mut u16,
            rirb_ctl: (base + 0x5C) as *mut u8,
            rirb_size: (base + 0x5E) as *mut u8,
            rirb_addr_l: (base + 0x50) as *mut u32,
            rirb_addr_h: (base + 0x54) as *mut u32,
            rirb_count: 256,
            rirb_rp_shadow: 0,

            icoi: (base + 0x60) as *mut u32,
            irii: (base + 0x64) as *mut u32,
            ics: (base + 0x68) as *mut u16,

            use_immediate: false,
        }
    }

    pub async unsafe fn init(&mut self, use_imm: bool) {
        self.use_immediate = use_imm;
    
        if self.use_immediate {
            write_volatile(self.corb_ctl, 0);
            write_volatile(self.rirb_ctl, 0);
            return;
        }

        
    
        let gctl_ptr = (self.base + 0x08) as *mut u32;
        write_volatile(gctl_ptr, read_volatile(gctl_ptr) | 0x1);
        serial_println!("GCTL after setting CRST: 0x{:08X}", read_volatile(gctl_ptr));
        while read_volatile(gctl_ptr) & 0x1 == 0 {
            serial_println!("Waiting for GCTL.CRST to be acknowledged");
        }
    
        nanosleep_current_event(100_000_000).unwrap().await;
    
        let cap = (read_volatile(self.corb_size) >> 4) & 0xF;
        self.corb_count = if cap & 0x4 != 0 {
            256
        } else if cap & 0x2 != 0 {
            16
        } else {
            2
        };
    
        write_volatile(self.corb_addr_l, self.corb_phys as u32);
        write_volatile(self.corb_addr_h, (self.corb_phys >> 32) as u32);
    
        for i in 0..self.corb_count {
            write_volatile(self.corb_virt.add(i), 0);
        }
    
        write_volatile(self.corb_size, (read_volatile(self.corb_size) & 0xF8) | 0x2);
    
        //ADD THE CORBRP RESET HERE
        let corbrp_ptr = (self.base + 0x4A) as *mut u16;
        assert!(self.corb_phys & 0x7F == 0);
        serial_println!("CORB_ADDR_L = 0x{:08X}", read_volatile(self.corb_addr_l));
        serial_println!("CORB_ADDR_H = 0x{:08X}", read_volatile(self.corb_addr_h));
        serial_println!("CORB_SIZE   = 0x{:02X}", read_volatile(self.corb_size));
        serial_println!("CORB_CTL    = 0x{:02X}", read_volatile(self.corb_ctl));
        serial_println!("CORB_RP     = 0x{:04X}", read_volatile(self.corb_rp));
        serial_println!("CORB_WP     = 0x{:04X}", read_volatile(self.corb_wp));
        serial_println!("CORB_PTR    = 0x{:X}", corbrp_ptr as usize);

        serial_println!("CORBRP register at: 0x{:X}", corbrp_ptr as usize);

        serial_println!("Sleeping before CORBRP reset");
        // nanosleep_current_event(10_000_000).unwrap().await; // 10 ms

        write_volatile(corbrp_ptr, 0x8000);
        while read_volatile(corbrp_ptr) & 0x8000 == 0 {
            serial_println!("Waiting for CORBRPRST to be latched by controller...");
        }

        let val = read_volatile(corbrp_ptr);
        serial_println!("CORBRP after write = 0x{:04X}", val);

        write_volatile(corbrp_ptr, 0x0000);
        while (read_volatile(corbrp_ptr) & 0x8000) != 0 {
            serial_println!("Waiting for controller to clear CORBRPRST");
        }
        

        write_volatile(self.corb_wp, 0);
    
        for i in 0..self.rirb_count {
            write_volatile(self.rirb_virt.add(i), 0);
        }
    
        let cap = (read_volatile(self.rirb_size) >> 4) & 0xF;
        self.rirb_count = if cap & 0x4 != 0 {
            256
        } else if cap & 0x2 != 0 {
            8
        } else {
            2
        };
    
        write_volatile(self.rirb_addr_l, self.rirb_phys as u32);
        write_volatile(self.rirb_addr_h, (self.rirb_phys >> 32) as u32);
        write_volatile(self.rirb_size, (read_volatile(self.rirb_size) & 0xF8) | 0x2);
        write_volatile(self.rirb_wp, RIRBWPRST);
        serial_println!("RIRBWP after reset: 0x{:04X}", read_volatile(self.rirb_wp));

        self.rirb_rp_shadow = 0;
    
        // serial_println!("CORB base low:   0x{:08x}", read_volatile(self.corb_addr_l));
        // serial_println!("CORB base high:  0x{:08x}", read_volatile(self.corb_addr_h));
        // serial_println!("CORB size:       0x{:08x}", read_volatile(self.corb_size));
        // serial_println!("CORB RP:         0x{:08x}", read_volatile(self.corb_rp));
        // serial_println!("CORB WP:         0x{:08x}", read_volatile(self.corb_wp));
        // serial_println!("CORB CTL:        0x{:08x}", read_volatile(self.corb_ctl));
    
        write_volatile(self.corb_ctl, CORBRUN);
        write_volatile(self.rirb_ctl, RIRBDMAEN | RINTCTL);
        serial_println!("---------------------------------------------");
        serial_println!("RIRB_CTL after enabling: 0x{:02X}", read_volatile(self.rirb_ctl));


        let intctl_ptr = (self.base + 0x20) as *mut u32;
        write_volatile(intctl_ptr, 0x80000000); // Enable global HDA interrupt (bit 31)
        serial_println!("INTCTL enabled: 0x{:08X}", read_volatile(intctl_ptr));
    
        // serial_println!("RIRB CTL:        0x{:02X}", read_volatile(self.rirb_ctl));
        // serial_println!("RIRB base low:   0x{:08X}", read_volatile(self.rirb_addr_l));
        // serial_println!("RIRB base high:  0x{:08X}", read_volatile(self.rirb_addr_h));
        // serial_println!("RIRB size:       0x{:02X}", read_volatile(self.rirb_size));
        // serial_println!("RIRB WP:         0x{:04X}", read_volatile(self.rirb_wp));
        // serial_println!("RIRB CTL:        0x{:02X}", read_volatile(self.rirb_ctl));
    }

    pub async unsafe fn send(&mut self, cmd: u32) -> u64 {
        if self.use_immediate {
            while read_volatile(self.ics) & ICB != 0 {}
            write_volatile(self.icoi, cmd);
            write_volatile(self.ics, read_volatile(self.ics) | ICB);
            while read_volatile(self.ics) & IRV == 0 {}
            let mut val = read_volatile(self.irii) as u64;
            val |= (read_volatile(self.irii) as u64) << 32;
            write_volatile(self.ics, read_volatile(self.ics) & !IRV);
            return val;
        }

        serial_println!("CORB_WP");
        while (read_volatile(self.corb_wp) & 0xff) != (read_volatile(self.corb_rp) & 0xff) {}
        let pos = ((read_volatile(self.corb_wp) + 1) % self.corb_count as u16) as usize;
        write_volatile(self.corb_virt.add(pos), cmd);
        write_volatile(self.corb_wp, pos as u16);
        serial_println!("CORBWP write pos: {}, value: 0x{:08X}", pos, cmd);


        // while (read_volatile(self.rirb_wp) & 0xff) == (self.rirb_rp_shadow & 0xff) {
        //     // serial_println!("RIRB_WP: 0x{:04X}", read_volatile(self.rirb_wp));
        //     nanosleep_current_event(100_000_000).unwrap().await;
        // }

        while (read_volatile(self.rirb_wp) & 0xff) == (self.rirb_rp_shadow & 0xff) {
            let wp = read_volatile(self.rirb_wp);
            serial_println!(
                "Waiting... RIRBWP: 0x{:04X}, Shadow: 0x{:04X}",
                wp,
                self.rirb_rp_shadow
            );

            for i in 0..4 {
                let val = read_volatile(self.rirb_virt.add(i));
                serial_println!("RIRB[{}] = 0x{:016X}", i, val);
            }

            nanosleep_current_event(100_000_000).unwrap().await;
        }
        
        // serial_println!("")
        let idx = ((self.rirb_rp_shadow + 1) % self.rirb_count as u16) as usize;
        let val = read_volatile(self.rirb_virt.add(idx));
        self.rirb_rp_shadow = idx as u16;
        serial_println!("val after sending command is 0x{:08X}", val);
        val
    }

    pub async fn set_use_immediate(&mut self, enable: bool) {
        self.use_immediate = enable;
    }

    pub async unsafe fn cmd12(&mut self, addr: WidgetAddr, verb: u32, data: u8) -> u64 {
        let mut n = 0u32;
        n |= ((addr.0 as u32 & 0xF) << 28) | ((addr.1 as u32 & 0xFF) << 20);
        n |= (verb & 0xFFF) << 8;
        n |= data as u32;
        self.send(n).await
    }

    pub async unsafe fn cmd4(&mut self, addr: WidgetAddr, verb: u32, data: u16) -> u64 {
        let mut n = 0u32;
        n |= ((addr.0 as u32 & 0xF) << 28) | ((addr.1 as u32 & 0xFF) << 20);
        n |= (verb & 0xF) << 16;
        n |= data as u32;
        self.send(n).await
    }
}
