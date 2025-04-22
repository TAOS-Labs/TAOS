//! I/O APIC
//!
//! - Allows for I/O APIC initialization and configuration
//! - Maps legacy IRQs to interrupt vectors
//! - Configures interrupt delivery to x2APIC
//! - Provides specific configurations for devices like PS/2 keyboard, mouse, etc.
//! - Supports masking/unmasking of specific IRQs

use crate::{
    constants::idt::{KEYBOARD_VECTOR, MOUSE_VECTOR, TIMER_VECTOR as PIT_VECTOR},
    memory::paging::map_kernel_frame,
    serial_println,
};
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;
use x86_64::{
    structures::paging::{Mapper, PageTableFlags, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

/// I/O APIC memory-mapped register indices
const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VER: u32 = 0x01;

// TODO: We need this???
#[allow(dead_code)]
const IOAPIC_REG_ARB: u32 = 0x02;
const IOAPIC_REG_REDTBL_BASE: u32 = 0x10;

/// I/O APIC memory-mapped register offsets
const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;

/// I/O APIC configuration flags
const IOAPIC_DELIVERY_FIXED: u64 = 0b000 << 8;
const IOAPIC_DELIVERY_LOWEST_PRIORITY: u64 = 0b001 << 8;
const IOAPIC_DELIVERY_SMI: u64 = 0b010 << 8;
const IOAPIC_DELIVERY_NMI: u64 = 0b100 << 8;
const IOAPIC_DELIVERY_INIT: u64 = 0b101 << 8;
const IOAPIC_DELIVERY_EXTINT: u64 = 0b111 << 8;

/// I/O APIC trigger mode flags
const IOAPIC_TRIGGER_EDGE: u64 = 0 << 15;
const IOAPIC_TRIGGER_LEVEL: u64 = 1 << 15;

/// I/O APIC polarity flags
const IOAPIC_POLARITY_HIGH_ACTIVE: u64 = 0 << 13;
const IOAPIC_POLARITY_LOW_ACTIVE: u64 = 1 << 13;

/// I/O APIC destination mode flags
const IOAPIC_DESTINATION_PHYSICAL: u64 = 0 << 11;
const IOAPIC_DESTINATION_LOGICAL: u64 = 1 << 11;

/// I/O APIC mask/unmask flags
const IOAPIC_MASKED: u64 = 1 << 16;
const IOAPIC_UNMASKED: u64 = 0 << 16;

/// Default I/O APIC base address
/// In a real implementation, we should get this from ACPI tables
/// For now, we hardcode to Qemu and pray it doesn't break on different machines
const DEFAULT_IOAPIC_PHYS_ADDR: PhysAddr = unsafe { PhysAddr::new_unsafe(0xFEC00000) };

/// I/O APIC IRQ configuration
#[derive(Debug, Clone, Copy)]
pub struct IoApicIrqConfig {
    /// Vector number to deliver
    pub vector: u8,
    /// Destination processor ID
    pub destination: u8,
    /// Whether interrupt is masked
    pub masked: bool,
    /// Trigger mode: edge or level
    pub trigger_mode: TriggerMode,
    /// Polarity: high or low active
    pub polarity: Polarity,
    /// Destination mode: physical or logical
    pub dest_mode: DestinationMode,
    /// Delivery mode: fixed, lowest priority, etc.
    pub delivery_mode: DeliveryMode,
}

/// Trigger mode for interrupts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    /// Edge-triggered interrupt
    Edge,
    /// Level-triggered interrupt
    Level,
}

/// Polarity for interrupts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    /// High active
    HighActive,
    /// Low active
    LowActive,
}

/// Destination mode for interrupts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationMode {
    /// Physical destination mode - send to specific CPU ID
    Physical,
    /// Logical destination mode - send to processors matching logical ID
    Logical,
}

/// Delivery mode for interrupts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// Fixed delivery to specified CPU
    Fixed,
    /// Send to processor with lowest priority
    LowestPriority,
    /// System Management Interrupt
    Smi,
    /// Non-Maskable Interrupt
    Nmi,
    /// INIT signal
    Init,
    /// External Interrupt
    ExtInt,
}

/// Errors that can occur during I/O APIC operations
#[derive(Debug)]
pub enum IoApicError {
    /// I/O APIC not found at expected address
    NotFound,
    /// Invalid IRQ number
    InvalidIrq,
    /// Failed to write to I/O APIC register
    WriteFailed,
    /// Failed to read from I/O APIC register
    ReadFailed,
    /// Unsupported feature or configuration
    UnsupportedFeature,
    /// Initialization failed
    InitFailed,
}

/// Global I/O APIC manager
pub static IO_APIC_MANAGER: Mutex<IoApicManager> = Mutex::new(IoApicManager::new());

/// Manages the I/O APIC for the system
pub struct IoApicManager {
    /// Physical address of the I/O APIC registers (for reference only after mapping)
    phys_addr: PhysAddr,
    /// Virtual address where I/O APIC registers are mapped
    virt_addr: Option<VirtAddr>,
    /// Whether the I/O APIC has been initialized
    initialized: bool,
    /// Maximum number of redirection entries supported
    max_redirection_entries: u8,
    /// Track level-triggered interrupt pin assertions
    /// TODO: Does it work?
    pin_assertions: [bool; 24],
}

impl Default for IoApicManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IoApicManager {
    /// Creates a new I/O APIC manager
    pub const fn new() -> Self {
        Self {
            phys_addr: DEFAULT_IOAPIC_PHYS_ADDR,
            virt_addr: None,
            initialized: false,
            max_redirection_entries: 0,
            pin_assertions: [false; 24],
        }
    }

    /// Initialize the I/O APIC with default mappings
    pub fn initialize(&mut self, mapper: &mut impl Mapper<Size4KiB>) -> Result<(), IoApicError> {
        if self.initialized {
            return Ok(());
        }

        // Map the I/O APIC registers to virtual memory using the paging system
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;

        // Map the physical I/O APIC address to a virtual address
        let phys_frame = PhysFrame::containing_address(self.phys_addr);
        let virt_addr = map_kernel_frame(mapper, phys_frame, flags);

        // Store the virtual address
        self.virt_addr = Some(virt_addr);

        // Read I/O APIC version to get maximum redirection entries
        let version_reg = self.read_register(IOAPIC_REG_VER)?;
        self.max_redirection_entries = ((version_reg >> 16) & 0xFF) as u8;

        serial_println!(
            "I/O APIC initialized: ID {}, Version {}, Max IRQs {}",
            self.get_id().unwrap_or(0),
            version_reg & 0xFF,
            self.max_redirection_entries + 1
        );

        // Mask all interrupts initially
        for irq in 0..=self.max_redirection_entries {
            self.mask_irq(irq)?;
        }

        self.setup_standard_irqs()?;

        self.initialized = true;
        Ok(())
    }

    /// Setup standard IRQ mappings for common devices
    fn setup_standard_irqs(&mut self) -> Result<(), IoApicError> {
        // PIT
        self.configure_irq(
            0,
            IoApicIrqConfig {
                vector: PIT_VECTOR,
                destination: 0, // BSP
                masked: false,  // Enable immediately
                trigger_mode: TriggerMode::Edge,
                polarity: Polarity::HighActive,
                dest_mode: DestinationMode::Physical,
                delivery_mode: DeliveryMode::Fixed,
            },
        )?;

        // Keyboard
        self.configure_irq(
            1,
            IoApicIrqConfig {
                vector: KEYBOARD_VECTOR,
                destination: 0, // BSP
                masked: false,  // Enable immediately
                trigger_mode: TriggerMode::Level,
                polarity: Polarity::LowActive,
                dest_mode: DestinationMode::Physical,
                delivery_mode: DeliveryMode::Fixed,
            },
        )?;

        // Mouse
        self.configure_irq(
            12,
            IoApicIrqConfig {
                vector: MOUSE_VECTOR,
                destination: 0, // BSP
                masked: false,  // Enable immediately
                trigger_mode: TriggerMode::Level,
                polarity: Polarity::LowActive,
                dest_mode: DestinationMode::Physical,
                delivery_mode: DeliveryMode::Fixed,
            },
        )?;

        // Mask everything else
        // TODO: Configure more as needed?
        for irq in (2..=11).chain(13..=self.max_redirection_entries) {
            if irq != 2 {
                // Skip IRQ 2 as it's typically connected to slave PIC
                // Do we need to talk to it?
                self.mask_irq(irq)?;
            }
        }

        Ok(())
    }

    /// Configure an IRQ with specific settings
    pub fn configure_irq(&mut self, irq: u8, config: IoApicIrqConfig) -> Result<(), IoApicError> {
        if irq > self.max_redirection_entries {
            return Err(IoApicError::InvalidIrq);
        }

        let mut low_bits: u64 = 0;
        let mut high_bits: u64 = 0;

        // Set vector
        low_bits |= config.vector as u64;

        // Set delivery mode
        low_bits |= match config.delivery_mode {
            DeliveryMode::Fixed => IOAPIC_DELIVERY_FIXED,
            DeliveryMode::LowestPriority => IOAPIC_DELIVERY_LOWEST_PRIORITY,
            DeliveryMode::Smi => IOAPIC_DELIVERY_SMI,
            DeliveryMode::Nmi => IOAPIC_DELIVERY_NMI,
            DeliveryMode::Init => IOAPIC_DELIVERY_INIT,
            DeliveryMode::ExtInt => IOAPIC_DELIVERY_EXTINT,
        };

        // Set destination mode
        low_bits |= match config.dest_mode {
            DestinationMode::Physical => IOAPIC_DESTINATION_PHYSICAL,
            DestinationMode::Logical => IOAPIC_DESTINATION_LOGICAL,
        };

        // Set polarity
        low_bits |= match config.polarity {
            Polarity::HighActive => IOAPIC_POLARITY_HIGH_ACTIVE,
            Polarity::LowActive => IOAPIC_POLARITY_LOW_ACTIVE,
        };

        // Set trigger mode
        low_bits |= match config.trigger_mode {
            TriggerMode::Edge => IOAPIC_TRIGGER_EDGE,
            TriggerMode::Level => IOAPIC_TRIGGER_LEVEL,
        };

        // Set mask
        low_bits |= if config.masked {
            IOAPIC_MASKED
        } else {
            IOAPIC_UNMASKED
        };

        // Set destination
        high_bits |= (config.destination as u64) << 24;

        // Write to redirection table
        let reg_index = IOAPIC_REG_REDTBL_BASE + (irq as u32 * 2);
        self.write_register(reg_index, low_bits)?;
        self.write_register(reg_index + 1, high_bits)?;

        Ok(())
    }

    /// Read a register from the I/O APIC
    fn read_register(&self, reg: u32) -> Result<u32, IoApicError> {
        let virt_addr = match self.virt_addr {
            Some(addr) => addr,
            None => return Err(IoApicError::NotFound),
        };

        let base_ptr = virt_addr.as_u64() as *mut u32;

        unsafe {
            write_volatile(base_ptr.add(IOREGSEL / 4), reg);
            Ok(read_volatile(base_ptr.add(IOWIN / 4)))
        }
    }

    /// Write to a register in the I/O APIC
    fn write_register(&self, reg: u32, value: u64) -> Result<(), IoApicError> {
        let virt_addr = match self.virt_addr {
            Some(addr) => addr,
            None => return Err(IoApicError::NotFound),
        };

        let base_ptr = virt_addr.as_u64() as *mut u32;

        unsafe {
            write_volatile(base_ptr.add(IOREGSEL / 4), reg);
            write_volatile(base_ptr.add(IOWIN / 4), value as u32);

            // If this is a 64-bit write, we need to write the high 32 bits
            if value > 0xFFFFFFFF {
                write_volatile(base_ptr.add(IOREGSEL / 4), reg + 1);
                write_volatile(base_ptr.add(IOWIN / 4), (value >> 32) as u32);
            }
        }

        Ok(())
    }

    /// Mask a specific IRQ
    pub fn mask_irq(&mut self, irq: u8) -> Result<(), IoApicError> {
        if irq > self.max_redirection_entries {
            return Err(IoApicError::InvalidIrq);
        }

        let reg_index = IOAPIC_REG_REDTBL_BASE + (irq as u32 * 2);
        let value = self.read_register(reg_index)?;
        self.write_register(reg_index, value as u64 | IOAPIC_MASKED)?;

        Ok(())
    }

    /// Unmask a specific IRQ
    pub fn unmask_irq(&mut self, irq: u8) -> Result<(), IoApicError> {
        if irq > self.max_redirection_entries {
            return Err(IoApicError::InvalidIrq);
        }

        let reg_index = IOAPIC_REG_REDTBL_BASE + (irq as u32 * 2);
        let value = self.read_register(reg_index)?;
        self.write_register(reg_index, (value as u64) & !IOAPIC_MASKED)?;

        Ok(())
    }

    /// Get the maximum number of IRQs supported by this I/O APIC
    pub fn get_max_irqs(&self) -> u8 {
        self.max_redirection_entries + 1
    }

    /// Get I/O APIC ID
    pub fn get_id(&self) -> Result<u32, IoApicError> {
        let id_reg = self.read_register(IOAPIC_REG_ID)?;
        Ok((id_reg >> 24) & 0xF)
    }

    /// Set I/O APIC ID
    pub fn set_id(&self, id: u8) -> Result<(), IoApicError> {
        let id_reg = self.read_register(IOAPIC_REG_ID)?;
        let new_id_reg = (id_reg & 0x00FFFFFF) | ((id as u32) << 24);
        self.write_register(IOAPIC_REG_ID, new_id_reg as u64)?;
        Ok(())
    }

    /// Handle a level-triggered interrupt. Call this when handling
    /// level-triggered interrupts to track assertions.
    pub fn handle_level_triggered_interrupt(&mut self, irq: u8) -> Result<(), IoApicError> {
        if irq > self.max_redirection_entries {
            return Err(IoApicError::InvalidIrq);
        }

        self.pin_assertions[irq as usize] = true;
        Ok(())
    }

    /// Clear level-triggered interrupt. Call this after the device
    /// has been serviced and the interrupt line is no longer asserted.
    pub fn clear_level_triggered_interrupt(&mut self, irq: u8) -> Result<(), IoApicError> {
        if irq > self.max_redirection_entries {
            return Err(IoApicError::InvalidIrq);
        }

        self.pin_assertions[irq as usize] = false;
        Ok(())
    }

    /// Get the physical address of the I/O APIC
    pub fn get_phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// Get the virtual address where the I/O APIC is mapped
    pub fn get_virt_addr(&self) -> Option<VirtAddr> {
        self.virt_addr
    }
}

/// Initialize the I/O APIC with the given page mapper
pub fn init(mapper: &mut impl Mapper<Size4KiB>) -> Result<(), IoApicError> {
    IO_APIC_MANAGER.lock().initialize(mapper)
}

/// Configure a specific IRQ
pub fn configure_irq(irq: u8, config: IoApicIrqConfig) -> Result<(), IoApicError> {
    IO_APIC_MANAGER.lock().configure_irq(irq, config)
}

/// Mask a specific IRQ
pub fn mask_irq(irq: u8) -> Result<(), IoApicError> {
    IO_APIC_MANAGER.lock().mask_irq(irq)
}

/// Unmask a specific IRQ
pub fn unmask_irq(irq: u8) -> Result<(), IoApicError> {
    IO_APIC_MANAGER.lock().unmask_irq(irq)
}

/// Configure PS/2 keyboard specifically
pub fn configure_ps2_keyboard(destination_cpu: u8) -> Result<(), IoApicError> {
    configure_irq(
        1, // IRQ 1 is PS/2 keyboard
        IoApicIrqConfig {
            vector: KEYBOARD_VECTOR,
            destination: destination_cpu,
            masked: false,
            trigger_mode: TriggerMode::Edge,
            polarity: Polarity::HighActive,
            dest_mode: DestinationMode::Physical,
            delivery_mode: DeliveryMode::Fixed,
        },
    )
}

/// Configure PS/2 mouse specifically
pub fn configure_ps2_mouse(destination_cpu: u8) -> Result<(), IoApicError> {
    configure_irq(
        12, // IRQ 12 is PS/2 mouse
        IoApicIrqConfig {
            vector: MOUSE_VECTOR,
            destination: destination_cpu,
            masked: false,
            trigger_mode: TriggerMode::Edge,
            polarity: Polarity::HighActive,
            dest_mode: DestinationMode::Physical,
            delivery_mode: DeliveryMode::Fixed,
        },
    )
}

/// Dump I/O APIC configuration for debugging
pub fn dump_io_apic_config() {
    let io_apic = IO_APIC_MANAGER.lock();
    serial_println!("I/O APIC Configuration:");

    if let Ok(id) = io_apic.get_id() {
        serial_println!("ID: {}", id);
    } else {
        serial_println!("Failed to read I/O APIC ID");
    }

    serial_println!("Physical Address: {:x}", io_apic.get_phys_addr().as_u64());
    if let Some(virt_addr) = io_apic.get_virt_addr() {
        serial_println!("Virtual Address: {:x}", virt_addr.as_u64());
    } else {
        serial_println!("Virtual Address: Not mapped");
    }

    let max_entries = io_apic.get_max_irqs();
    serial_println!("Max redirection entries: {}", max_entries);

    for irq in 0..max_entries {
        let reg_index = IOAPIC_REG_REDTBL_BASE + (irq as u32 * 2);

        if let Ok(low) = io_apic.read_register(reg_index) {
            if let Ok(high) = io_apic.read_register(reg_index + 1) {
                let vector = low & 0xFF;
                let delivery = (low >> 8) & 0x7;
                let dest_mode = (low >> 11) & 0x1;
                let polarity = (low >> 13) & 0x1;
                let trigger = (low >> 15) & 0x1;
                let masked = (low >> 16) & 0x1;
                let destination = high >> 24;

                serial_println!("IRQ {}: vector={}, delivery={}, dest_mode={}, polarity={}, trigger={}, masked={}, dest={}",
                    irq, vector, delivery, dest_mode, polarity, trigger, masked, destination);
            }
        }
    }
}
