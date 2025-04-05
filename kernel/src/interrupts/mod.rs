//! CPU interrupt and exception handling subsystem.
//!
//! Provides initialization and management of:
//! - Global Descriptor Table (GDT)
//! - Interrupt Descriptor Table (IDT)
//! - Advanced Programmable Interrupt Controller (x2APIC)
//! - Exception handlers and interrupt handling

use crate::{constants::x2apic::CPU_FREQUENCY, memory::MAPPER};

pub mod gdt;
pub mod idt;
pub mod io_apic;
pub mod x2apic;

/// Initialize interrupt handling for a CPU core.
///
/// - Loads the GDT and TSS
/// - Sets up the IDT with exception handlers
/// - Initializes the x2APIC (differently for BSP vs AP cores)
///
/// # Arguments
/// * `cpu_id` - ID of the CPU being initialized (0 for BSP, >0 for APs)
///
/// # Panics
/// Panics if x2APIC initialization fails for either BSP or AP
pub fn init(cpu_id: u32) {
    gdt::init(cpu_id);
    idt::init_idt(cpu_id);
    if cpu_id == 0 {
        x2apic::init_bsp(CPU_FREQUENCY).expect("Failed to configure x2APIC");

        {
            let mut mapper = MAPPER.lock();
            io_apic::init(&mut *mapper).expect("Failed to initialize I/O APIC");
        }
    } else {
        x2apic::init_ap().expect("Failed to initialize core APIC");
    }
}
