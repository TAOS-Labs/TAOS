// IDK if we need this
// We'll transcribe just in case.

use alloc::boxed::Box;
use async_trait::async_trait;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;
use x86_64::instructions::port::{Port, PortReadOnly, PortWriteOnly};

use super::block_io::{BlockError, BlockIO, BlockResult};

const SECTOR_SIZE: usize = 512;

// IDE Status Register bits
const ERR: u8 = 0x01;
const DRQ: u8 = 0x08;
const DF: u8 = 0x20;
const DRDY: u8 = 0x40;
const BSY: u8 = 0x80;

// Base I/O ports for controllers
const IDE_PORTS: [u16; 2] = [0x1f0, 0x170];

// IDE Commands
const CMD_READ: u8 = 0x20; // Read with retry
const CMD_WRITE: u8 = 0x30; // Write with retry

/// Statistics for IDE operations
#[derive(Default)]
pub struct IdeStats {
    reads: AtomicU32,
    writes: AtomicU32,
}

impl IdeStats {
    pub fn get_stats(&self) -> (u32, u32) {
        (
            self.reads.load(Ordering::Relaxed),
            self.writes.load(Ordering::Relaxed),
        )
    }
}

/// Low-level IDE register access
struct IdeRegisters {
    data_port: Port<u32>,
    sector_count_port: PortWriteOnly<u8>,
    lba_low_port: PortWriteOnly<u8>,
    lba_mid_port: PortWriteOnly<u8>,
    lba_high_port: PortWriteOnly<u8>,
    device_port: PortWriteOnly<u8>,
    command_port: PortWriteOnly<u8>,
    status_port: PortReadOnly<u8>,
}

// SAFETY: All register operations are unsafe and must be properly synchronized
impl IdeRegisters {
    unsafe fn new(base_port: u16) -> Self {
        Self {
            data_port: Port::new(base_port),
            sector_count_port: PortWriteOnly::new(base_port + 2),
            lba_low_port: PortWriteOnly::new(base_port + 3),
            lba_mid_port: PortWriteOnly::new(base_port + 4),
            lba_high_port: PortWriteOnly::new(base_port + 5),
            device_port: PortWriteOnly::new(base_port + 6),
            command_port: PortWriteOnly::new(base_port + 7),
            status_port: PortReadOnly::new(base_port + 7),
        }
    }

    unsafe fn read_status(&mut self) -> u8 {
        self.status_port.read()
    }

    unsafe fn read_data(&mut self, buffer: &mut [u8]) -> BlockResult<()> {
        let words = buffer.as_mut_ptr() as *mut u32;
        for i in 0..SECTOR_SIZE / 4 {
            *words.add(i) = self.data_port.read();
        }
        Ok(())
    }

    unsafe fn write_data(&mut self, buffer: &[u8]) -> BlockResult<()> {
        let words = buffer.as_ptr() as *const u32;
        for i in 0..SECTOR_SIZE / 4 {
            self.data_port.write(*words.add(i));
        }
        Ok(())
    }

    unsafe fn setup_transfer(
        &mut self,
        channel: u8,
        sector: u64,
        is_write: bool,
    ) -> BlockResult<()> {
        self.sector_count_port.write(1);
        self.lba_low_port.write((sector & 0xFF) as u8);
        self.lba_mid_port.write(((sector >> 8) & 0xFF) as u8);
        self.lba_high_port.write(((sector >> 16) & 0xFF) as u8);
        self.device_port
            .write(0xE0 | (channel << 4) | ((sector >> 24) & 0x0F) as u8);
        self.command_port
            .write(if is_write { CMD_WRITE } else { CMD_READ });
        Ok(())
    }
}

/// Safe interface to an IDE drive
pub struct Ide {
    drive: u8,
    regs: Mutex<IdeRegisters>,
    stats: IdeStats,
}

impl Ide {
    pub fn new(drive: u8) -> Self {
        Self {
            drive,
            // SAFETY: Port initialization is safe when using correct IDE ports
            regs: Mutex::new(unsafe { IdeRegisters::new(IDE_PORTS[((drive >> 1) & 1) as usize]) }),
            stats: IdeStats::default(),
        }
    }

    fn channel(&self) -> u8 {
        self.drive & 1
    }

    async fn wait_until_ready(&self) -> BlockResult<()> {
        let mut regs = self.regs.lock();

        // SAFETY: Port access is synchronized via mutex
        unsafe {
            let status = regs.read_status();
            if (status & (ERR | DF)) != 0 {
                return Err(BlockError::DeviceError);
            }

            if (status & DRDY) == 0 {
                return Err(BlockError::DeviceError);
            }

            while (regs.read_status() & BSY) != 0 {
                core::hint::spin_loop();
            }
        }

        Ok(())
    }

    fn wait_for_data(&self) -> BlockResult<()> {
        let mut regs = self.regs.lock();

        // SAFETY: Port access is synchronized via mutex
        unsafe {
            while (regs.read_status() & DRQ) == 0 {
                core::hint::spin_loop();
            }
        }

        Ok(())
    }
}

#[async_trait]
impl BlockIO for Ide {
    fn block_size(&self) -> u64 {
        SECTOR_SIZE as u64
    }

    fn size_in_bytes(&self) -> u64 {
        // TODO: Implement proper drive size detection
        u32::MAX as u64
    }

    async fn read_block(&self, block_number: u64, buffer: &mut [u8]) -> BlockResult<()> {
        if buffer.len() < SECTOR_SIZE {
            return Err(BlockError::InvalidBlock);
        }

        self.stats.reads.fetch_add(1, Ordering::Relaxed);

        self.wait_until_ready().await?;

        {
            let mut regs = self.regs.lock();
            // SAFETY: Port access is synchronized via mutex
            unsafe {
                regs.setup_transfer(self.channel(), block_number, false)?;
            }
        }

        self.wait_until_ready().await?;
        self.wait_for_data()?;

        let mut regs = self.regs.lock();
        // SAFETY: Port access is synchronized and buffer size is verified
        unsafe { regs.read_data(buffer) }
    }

    async fn read_sector(&self, block_number: u64, buffer: &mut [u8]) -> BlockResult<()> {
        self.read_block(block_number, buffer).await
    }

    async fn write_block(&self, block_number: u64, buffer: &[u8]) -> BlockResult<()> {
        if buffer.len() < SECTOR_SIZE {
            return Err(BlockError::InvalidBlock);
        }

        self.stats.writes.fetch_add(1, Ordering::Relaxed);

        self.wait_until_ready().await?;

        {
            let mut regs = self.regs.lock();
            // SAFETY: Port access is synchronized via mutex
            unsafe {
                regs.setup_transfer(self.channel(), block_number, true)?;
            }
        }

        self.wait_until_ready().await?;
        self.wait_for_data()?;

        let mut regs = self.regs.lock();
        // SAFETY: Port access is synchronized and buffer size is verified
        unsafe {
            regs.write_data(buffer)?;
        }

        self.wait_until_ready().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    async fn test_ide_ports() {
        let ide = Ide::new(0);
        assert_eq!(ide.drive, 0); // Primary master

        let ide = Ide::new(2);
        assert_eq!(ide.drive, 2); // Secondary master
    }

    #[test_case]
    async fn test_block_size() {
        let ide = Ide::new(0);
        assert_eq!(ide.block_size(), SECTOR_SIZE as u64);
    }
}
