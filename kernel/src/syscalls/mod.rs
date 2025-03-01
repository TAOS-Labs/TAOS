pub mod fork;
pub mod mmap;
pub mod syscall_handlers;

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use syscall_handlers::TEST_EXIT_CODE;

    use crate::{
        constants::processes::TEST_64_SIMPLE_EXIT, events::schedule_process,
        processes::process::create_process,
    };

    use super::*;

    #[test_case]
    fn test_exit_code() {
        let pid = create_process(TEST_64_SIMPLE_EXIT);
        schedule_process(pid);

        while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
            core::hint::spin_loop();
        }

        assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);
    }
}
