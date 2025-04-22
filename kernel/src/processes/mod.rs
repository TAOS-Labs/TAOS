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
    use alloc::vec;
    use x86_64::align_up;

    use crate::{
        constants::{memory::PAGE_SIZE, processes::TEST_SIMPLE_PROCESS},
        events::{
            current_running_event, futures::await_on::AwaitProcess, get_runner_time,
            schedule_process,
        },
        filesys::{get_file, FileSystem, OpenFlags, FILESYSTEM},
        processes::process::create_process,
        serial_println,
        syscalls::memorymap::{sys_mmap, MmapFlags, ProtFlags},
    };

    #[test_case]
    async fn test_simple_process() {
        let pid = create_process(TEST_SIMPLE_PROCESS);
        schedule_process(pid);
        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        ) // TODO how to get event corresponding to testcase?
        .await;
        assert!(waiter.is_ok());
    }

    #[test_case]
    async fn test_simple_c_ret() {
        let fs = FILESYSTEM.get().unwrap();
        let fd = {
            fs.lock()
                .open_file(
                    "/executables/ret",
                    OpenFlags::O_RDONLY | OpenFlags::O_WRONLY,
                )
                .await
                .expect("Could not open file")
        };
        let file = get_file(fd).unwrap();
        let file_len = {
            fs.lock()
                .filesystem
                .lock()
                .get_node(&file.lock().pathname)
                .await
                .unwrap()
                .size()
        };
        sys_mmap(
            0x9000,
            align_up(file_len, PAGE_SIZE as u64),
            ProtFlags::PROT_EXEC.bits(),
            MmapFlags::MAP_FILE.bits(),
            fd as i64,
            0,
        );

        serial_println!("Reading file...");

        let mut buffer = vec![0u8; file_len as usize];
        let bytes_read = {
            fs.lock()
                .read_file(fd, &mut buffer)
                .await
                .expect("Failed to read file")
        };

        let buf = &buffer[..bytes_read];

        serial_println!("Bytes read: {:#?}", bytes_read);

        let pid = create_process(buf);
        schedule_process(pid);
        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;
        assert!(waiter.is_ok());
    }
}
