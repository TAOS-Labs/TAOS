pub mod loader;
pub mod process;
pub mod registers;

#[cfg(test)]
mod tests {
    use crate::{
        constants::processes::INFINITE_LOOP, events::schedule_process, interrupts::x2apic,
        processes::process::create_process,
    };

    #[test_case]
    fn test_simple_process() {
        let cpuid = x2apic::current_core_id() as u32;

        let pid = create_process(INFINITE_LOOP);
        schedule_process(pid);

        assert!(matches!(cpuid, 0));
    }
}
