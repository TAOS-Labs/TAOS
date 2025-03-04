pub mod fork;
pub mod mmap;
pub mod syscall_handlers;

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use syscall_handlers::TEST_EXIT_CODE;

    use crate::{
        constants::processes::{TEST_64_FORK_COW, TEST_64_FORK_EXIT, TEST_64_PRINT_EXIT, TEST_64_SIMPLE_EXIT},
        events::schedule_process_on,
        processes::process::create_process, serial_println,
    };

    use super::*;

    /// The binary exits with code 0 immediately
    // #[test_case]
    fn test_exit_code() {
        let pid = create_process(TEST_64_SIMPLE_EXIT);
        schedule_process_on(1, pid);

        while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
            core::hint::spin_loop();
        }

        assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);

        TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);
    }

    /// The binary prints something to the console and then exits
    /// For now, requires manual verification that the printed
    /// content is correct 
    // #[test_case]
    fn test_print_exit() {
        let pid = create_process(TEST_64_PRINT_EXIT);
        schedule_process_on(1, pid);

        while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
            core::hint::spin_loop();
        }

        assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);

        TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);
    }

    /// Creates a child process, then sleeps for a non-negligible amount of time.
    /// Then, exits with the child_process pid. The child process exits with 0
    /// We should see the child exit first
    // #[test_case]
    fn test_fork_simple() {
        let parent_pid = create_process(TEST_64_FORK_EXIT);
        schedule_process_on(1, parent_pid);

        // Child exit
        while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
            core::hint::spin_loop();
        }

        assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);

        TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);

        // Parent exit
        while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
            core::hint::spin_loop();
        }

        assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), (parent_pid + 1) as i64);

        TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);
    }

    /// Creates a child process, then sleeps for a non-negligible amount of time.
    /// Then, exits with the child_process pid. The child process exits with 0
    /// We should see the child exit first
    // #[test_case]
    fn test_fork_cow() {
        let parent_pid = create_process(TEST_64_FORK_COW);
        schedule_process_on(1, parent_pid);

        // Child exit
        while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
            core::hint::spin_loop();
        }

        assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);

        TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);

        // Parent exit
        while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
            core::hint::spin_loop();
        }

        assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);

        TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);
    }
}
