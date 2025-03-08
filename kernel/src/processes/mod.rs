use process::create_placeholder_process;

pub mod loader;
pub mod process;
pub mod registers;

pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        create_placeholder_process();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::processes::RAND_REGS_EXIT, events::schedule_process, interrupts::x2apic,
        processes::process::create_process,
    };

    // #[test_case]
    fn test_simple_process() {
        let cpuid = x2apic::current_core_id() as u32;

        let pid = create_process(RAND_REGS_EXIT);
        unsafe {
            schedule_process(pid);
        }

        assert!(matches!(cpuid, 0));
    }
}
