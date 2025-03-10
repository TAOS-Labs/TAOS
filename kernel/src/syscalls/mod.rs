pub mod fork;
pub mod memorymap;
pub mod syscall_handlers;

#[cfg(test)]
mod tests {
    use core::{borrow::Borrow, sync::atomic::Ordering};

    use syscall_handlers::EXIT_CODES;

    use crate::{
        constants::processes::{TEST_EXIT_CODE, TEST_PRINT_EXIT},
        events::{
            current_running_event, futures::await_on::AwaitProcess, get_runner_time,
            schedule_process,
        },
        processes::process::create_process,
    };

    use super::*;

    /// The binary exits with code 0 immediately
    #[test_case]
    async fn test_exit_code() {
        let pid = create_process(TEST_EXIT_CODE);
        schedule_process(pid);

        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert!(waiter.is_ok());
        assert_eq!(EXIT_CODES.lock().get(&pid).unwrap(), &0);
    }

    /// The binary prints something to the console and then exits
    /// For now, requires manual verification that the printed
    /// content is correct
    #[test_case]
    async fn test_print_exit() {
        let pid = create_process(TEST_PRINT_EXIT);
        schedule_process(pid);

        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert!(waiter.is_ok());
        assert_eq!(EXIT_CODES.lock().get(&pid).unwrap(), &0);
    }

    /// Creates a child process, then sleeps for a non-negligible amount of time.
    /// Then, exits with the child_process pid. The child process exits with 0
    /// We should see the child exit first
    #[test_case]
    async fn test_fork_simple() {

    }

    //
    // // #[test_case]
    // async fn test_fork_simple() {
    //     let parent_pid = create_process(TEST_64_FORK_EXIT);
    //     schedule_process_on(1, parent_pid);
    //
    //     // Child exit
    //     while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
    //         core::hint::spin_loop();
    //     }
    //
    //     assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);
    //
    //     TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);
    //
    //     // Parent exit
    //     while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
    //         core::hint::spin_loop();
    //     }
    //
    //     assert_eq!(
    //         TEST_EXIT_CODE.load(Ordering::SeqCst),
    //         (parent_pid + 1) as i64
    //     );
    //
    //     TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);
    // }
    //
    // /// Creates a child process, then sleeps for a non-negligible amount of time.
    // /// Then, exits with the child_process pid. The child process exits with 0
    // /// We should see the child exit first
    // // #[test_case]
    // async fn test_fork_cow() {
    //     let parent_pid = create_process(TEST_64_FORK_COW);
    //     schedule_process_on(1, parent_pid);
    //
    //     // Child exit
    //     while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
    //         core::hint::spin_loop();
    //     }
    //
    //     assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);
    //
    //     TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);
    //
    //     // Parent exit
    //     while TEST_EXIT_CODE.load(Ordering::SeqCst) == i64::MIN {
    //         core::hint::spin_loop();
    //     }
    //
    //     assert_eq!(TEST_EXIT_CODE.load(Ordering::SeqCst), 0);
    //
    //     TEST_EXIT_CODE.store(i64::MIN, Ordering::SeqCst);
    // }
}
