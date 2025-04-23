use alloc::{fmt::format, string::ToString};

use crate::{
    devices::ps2_dev::keyboard,
    events::yield_now,
    serial_println,
    syscalls::syscall_handlers::{sys_exec, sys_read, sys_write},
};

// src/shell.rs
pub struct Shell {
    buffer: [u8; 256],
    position: usize,
}

impl Shell {
    pub fn new() -> Self {
        Self {
            buffer: [0; 256],
            position: 0,
        }
    }

    pub async fn run(&mut self) {
        serial_println!("SHELL RUNNING");
        self.print_prompt(); // Initial prompt

        loop {
            let c = self.read_char();

            match c {
                b'\n' | b'\r' => {
                    self.execute_command().await;
                    keyboard::flush_buffer();
                    self.print_prompt();
                }
                0x08 => self.handle_backspace(),
                _ if c.is_ascii_graphic() || c == b' ' => {
                    self.handle_char(c);
                }
                _ => { /* ignore everything else */ }
            }
            yield_now().await;
        }
    }

    fn read_char(&mut self) -> u8 {
        let mut c: u8 = 0;
        sys_read(0, &mut c as *mut u8, 1);

        // Echo handling for normal characters
        match c {
            b'\n' => {
                // Enter handled separately
            }
            0x08 => {
                // Backspace handled separately
            }
            _ => {
                // Only print printable ASCII characters
                if c.is_ascii_graphic() || c == b' ' {
                    self.print(&format(format_args!("{}", c as char)));
                }
            }
        }
        c
    }

    fn print(&self, s: &str) {
        sys_write(1, s.as_ptr() as *mut u8, s.len());
    }

    fn handle_char(&mut self, c: u8) {
        if self.position < self.buffer.len() - 1 {
            self.buffer[self.position] = c;
            self.position += 1;
        }
    }

    fn handle_backspace(&mut self) {
        if self.position > 0 {
            self.position -= 1;
            self.print("\x08 \x08");
        }
    }

    async fn execute_command(&mut self) {
        self.print("\r"); // return to start of line
        let cmd = core::str::from_utf8(&self.buffer[..self.position]).unwrap_or("Invalid UTF-8");

        self.print("\n");
        self.process_command(cmd);
        self.position = 0;
    }

    fn process_command(&self, cmd: &str) {
        match cmd.trim() {
            "" => {}
            "help" => self.print("Available commands: help, echo, clear\n"),
            "clear" => self.print("\x1B[2J\x1B[H"), // ANSI clear screen
            trimmed if trimmed.starts_with("echo ") => {
                // Use trimmed, not cmd, since that's what was matched
                let text = trimmed.strip_prefix("echo ").unwrap();
                self.print(&format(format_args!("{}\n", text)));
            }
            trimmed if trimmed.starts_with("/") => {
                let mut cmd_owned = trimmed.to_string() + "\0";
                // TODO: as of now we do not support cmd args or environment vars
                sys_exec(
                    cmd_owned.as_mut_ptr(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                );
            }
            _ => self.print("Unknown command\n"),
        }
    }

    fn print_prompt(&self) {
        self.print("> ");
    }
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
/// TODO
pub async unsafe fn init() {
    keyboard::flush_buffer();
    let mut shell = Shell::new();
    shell.run().await;
}
