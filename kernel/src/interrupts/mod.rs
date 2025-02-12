use crate::constants::x2apic::CPU_FREQUENCY;

pub mod gdt;
pub mod idt;
pub mod x2apic;

pub fn init(cpu_id: u32) {
    gdt::init(cpu_id);
    idt::init_idt(cpu_id);
    if cpu_id == 0 {
        // bsp
        x2apic::init_bsp(CPU_FREQUENCY).expect("Failed to configure x2APIC");
    } else {
        x2apic::init_ap().expect("Failed to initialize core APIC");
    }
}
