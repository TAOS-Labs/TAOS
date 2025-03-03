pub mod loader;
pub mod process;
pub mod registers;

#[cfg(test)]
mod tests {
    use crate::{
        constants::processes::SYSCALL_EXIT_TEST, 
        events::{
            current_running_event, 
            futures::await_on::AwaitProcess, 
            get_runner_time, 
            schedule_process}, 
        processes::process::create_process,
    };

    #[test_case]
    async fn test_simple_process() {
        let pid = create_process(SYSCALL_EXIT_TEST);
        schedule_process(pid);
        let waiter = AwaitProcess::new(pid, 
                get_runner_time(3_000_000_000), 
                current_running_event().unwrap())    // TODO how to get event corresponding to testcase?
        .await;

        assert!(waiter.is_ok());
    }
}
