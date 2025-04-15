use core::ptr::{read_volatile, write_volatile};
use crate::{devices::audio::dma::DmaBuffer, events::nanosleep_current_event, memory::HHDM_OFFSET, serial_println};

const CORBRUN: u8 = 1 << 1;
const CORBRPRST: u16 = 1 << 15;
const RIRBDMAEN: u8 = 1 << 1;
const RINTCTL: u8 = 1 << 0;
const RIRBWPRST: u16 = 1 << 15;
const ICB: u16 = 1 << 0;
const IRV: u16 = 1 << 1;

#[derive(Copy, Clone)]
pub struct WidgetAddr(pub u8, pub u8);

pub struct CommandBuffer {
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
        let base = (HHDM_OFFSET.as_u64() + base as u64) as usize;

        Self {
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
        write_volatile(self.corb_rp, CORBRPRST);
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
        self.rirb_rp_shadow = 0;

        serial_println!("CORB base low:   0x{:08x}", read_volatile(self.corb_addr_l));
        serial_println!("CORB base high:  0x{:08x}", read_volatile(self.corb_addr_h));
        serial_println!("CORB size:       0x{:08x}", read_volatile(self.corb_size));
        serial_println!("CORB RP:         0x{:08x}", read_volatile(self.corb_rp));
        serial_println!("CORB WP:         0x{:08x}", read_volatile(self.corb_wp));
        serial_println!("CORB CTL:        0x{:08x}", read_volatile(self.corb_ctl));

        write_volatile(self.corb_ctl, CORBRUN);
        write_volatile(self.corb_rp, 0);   

        while read_volatile(self.corb_rp) & CORBRPRST != 0 {
            serial_println!("Waiting forr CORBRPRST to be clear");
        }
        write_volatile(self.rirb_ctl, RIRBDMAEN | RINTCTL);
        serial_println!("RIRB CTL: 0x{:02X}", read_volatile(self.rirb_ctl));
        serial_println!("RIRB base low:   0x{:08X}", read_volatile(self.rirb_addr_l));
        serial_println!("RIRB base high:  0x{:08X}", read_volatile(self.rirb_addr_h));
        serial_println!("RIRB size:       0x{:02X}", read_volatile(self.rirb_size));
        serial_println!("RIRB WP:         0x{:04X}", read_volatile(self.rirb_wp));
        serial_println!("RIRB CTL:        0x{:02X}", read_volatile(self.rirb_ctl));

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


        while (read_volatile(self.rirb_wp) & 0xff) == (self.rirb_rp_shadow & 0xff) {
            // serial_println!("RIRB_WP: 0x{:04X}", read_volatile(self.rirb_wp));
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
        serial_println!("Sending verub: 0x{:08X}", n);
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
