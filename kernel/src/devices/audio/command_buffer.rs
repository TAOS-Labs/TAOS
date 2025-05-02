use core::ptr::{read_volatile, write_volatile};
use crate::devices::audio::dma::DmaBuffer;

use super::commands::{CorbEntry, RirbEntry};

// These bitflags are not a bad idea, they should have been actual bitflags types and we should have used them
// TODO: refactor some of this code to be nicer.
// const CORBRUN: u8 = 1 << 1;
// const CORBRPRST: u16 = 1 << 15;
// const RIRBDMAEN: u8 = 1 << 1;
// const RINTCTL: u8 = 1 << 0;
// const RIRBWPRST: u16 = 1 << 15;
// const ICB: u16 = 1 << 0;
// const IRV: u16 = 1 << 1;

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

        let write_address = (self.base + next_write as u64 * 4) as *mut CorbEntry;
        write_volatile(write_address, cmd);

        self.write_idx = next_write;
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

        let read_addr = (self.base + (next_idx as u64 * 8)) as *mut RirbEntry;
        let response = read_volatile(read_addr);

        self.read_idx = next_idx;
        response
    }


    
}
