use alloc::fmt::format;

use crate::{
    serial_print, serial_println,
    syscalls::syscall_handlers::{sys_read, sys_write},
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

    pub fn run(&mut self) -> ! {
        serial_println!("SHELL RUNNING");
        self.print_prompt(); // Initial prompt

        loop {
            let c = self.read_char();

            match c {
                b'\n' => {
                    self.execute_command();
                    self.print_prompt();
                }
                0x08 => self.handle_backspace(),
                _ => self.handle_char(c),
            }
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

    fn execute_command(&mut self) {
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
            cmd if cmd.starts_with("echo ") => {
                let text = cmd.strip_prefix("echo ").unwrap();
                self.print(&format(format_args!("{}\n", text)));
            }
            _ => self.print(&format(format_args!("Unknown command: {}\n", cmd))),
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
pub unsafe fn init() -> ! {
    let mut shell = Shell::new();
    shell.run();
}
