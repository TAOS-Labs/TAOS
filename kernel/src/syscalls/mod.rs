pub mod fork;
pub mod memorymap;
pub mod syscall_handlers;

#[cfg(test)]
mod tests {
    use syscall_handlers::EXIT_CODES;

    use crate::{
        constants::processes::{TEST_EXIT_CODE, TEST_FORK_COW, TEST_PRINT_EXIT, TEST_WAIT},
        events::{
            current_running_event, futures::await_on::AwaitProcess, get_runner_time,
            schedule_process,
        },
        processes::process::create_process,
        serial_println,
        syscalls::syscall_handlers::REGISTER_VALUES,
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
    // #[test_case]
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

    /// Creates a child process, then waits on it.
    ///
    /// The child process simply exits with code 5.
    /// The parent should be able to get this code
    /// and then exit with it after it is woken up
    /// from waiting
    // #[test_case]
    async fn test_fork_wait() {
        let pid = create_process(TEST_WAIT);
        schedule_process(pid);

        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert!(waiter.is_ok());
        assert_eq!(EXIT_CODES.lock().get(&pid).unwrap(), &5);
    }

    /// Creates a child process, and both processes try
    /// to write to the same COW buffer
    ///
    /// Child process exits with code 0, and parent process
    /// exits with code equivalent to child process PID.
    /// Currently, requires manual verification of buffer
    // #[test_case]
    async fn test_fork_cow() {
        let pid = create_process(TEST_FORK_COW);
        schedule_process(pid);

        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert!(waiter.is_ok());
        // verify that parent exited with child_pid (currently parent_pid + 1)
        assert_eq!(EXIT_CODES.lock().get(&pid).unwrap(), &(pid as i64 + 1));
        assert_eq!(EXIT_CODES.lock().get(&(pid + 1)).unwrap(), &0);
    }
}
