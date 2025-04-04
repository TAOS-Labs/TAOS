pub mod loader;
pub mod process;
pub mod registers;

use process::create_placeholder_process;

pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        create_placeholder_process();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        constants::processes::TEST_SIMPLE_PROCESS,
        events::{
            current_running_event, futures::await_on::AwaitProcess, get_runner_time,
            schedule_process,
        },
        processes::process::create_process,
        serial_println,
    };

    // #[test_case]
    async fn test_simple_process() {
        let pid = create_process(TEST_SIMPLE_PROCESS);
        schedule_process(pid);
        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        ) // TODO how to get event corresponding to testcase?
        .await;
        serial_println!("AWAITED");

        assert!(waiter.is_ok());
    }
}
