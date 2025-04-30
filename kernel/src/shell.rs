use alloc::{
    fmt::format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    devices::ps2_dev::keyboard,
    events::schedule_kernel,
    serial_println,
    syscalls::{
        block::spin_on,
        syscall_handlers::{sys_exec, sys_read, sys_write},
    },
};

pub struct Shell {
    buffer: [u8; 256],
    position: usize,
    env: Vec<String>,
}
impl Shell {
    pub fn new() -> Self {
        Self {
            buffer: [0; 256],
            position: 0,
            env: Vec::new(),
        }
    }
    pub fn run(self) {
        serial_println!("SHELL RUNNING");
        self.print_prompt();
        let mut i = 0;

        schedule_kernel(
            async move {
                let mut shell = self;
                loop {
                    let c = shell.read_char();
                    match c {
                        b'\n' | b'\r' => {
                            shell.execute_command().await;
                            keyboard::flush_buffer().await;
                            shell.print_prompt();
                            serial_println!("ENVS: {:#?}", shell.env);
                            // TODO: Until the heap allocation error is fixed arbitrary number of
                            // commands allowed to run
                            i += 1;
                            if i == 5 {
                                return;
                            }
                        }
                        0x08 => shell.handle_backspace(),
                        _ if c.is_ascii_graphic() || c == b' ' => shell.handle_char(c),
                        _ => {}
                    }
                    // yield_now().await
                }
            },
            3,
        );
    }

    fn read_char(&mut self) -> u8 {
        let mut c: u8 = 0;
        unsafe { spin_on(sys_read(0, &mut c as *mut u8, 1)) };
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
        unsafe { spin_on(sys_write(1, s.as_ptr() as *mut u8, s.len())) };
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
        let cmd_owned = {
            let slice = &self.buffer[..self.position];
            String::from_utf8_lossy(slice).to_string()
        };
        self.print("\n");
        self.process_command(&cmd_owned);
        self.position = 0;
    }

    fn process_command(&mut self, cmd: &str) {
        let trimmed = cmd.trim();
        match trimmed {
            "" => {}

            "help" => self.print("Available: help, echo, clear, export, [/cmd]\n"),

            "clear" => self.print("\x1B[2J\x1B[H"),

            t if t.starts_with("echo ") => {
                let raw = t.strip_prefix("echo ").unwrap();
                // simple var‐expansion: $VAR or ${VAR}
                let mut out = String::new();
                let mut chars = raw.chars().peekable();
                while let Some(c) = chars.next() {
                    // At this point we know that we're printing out an environment variable
                    if c == '$' {
                        // detect ${VAR} vs $VAR
                        let name = if chars.peek() == Some(&'{') {
                            chars.next(); // skip '{'
                            let mut nm = String::new();
                            while let Some(&nx) = chars.peek() {
                                if nx == '}' {
                                    chars.next();
                                    break;
                                }
                                nm.push(nx);
                                chars.next();
                            }
                            nm
                        } else {
                            let mut nm = String::new();
                            while let Some(&next) = chars.peek() {
                                if !next.is_ascii_alphanumeric() && next != '_' {
                                    break;
                                }
                                nm.push(next);
                                chars.next();
                            }
                            nm
                        };
                        // lookup NAME in self.env
                        let val = self
                            .env
                            .iter()
                            .find_map(|kv| {
                                let mut sp = kv.splitn(2, '=');
                                if sp.next()? == name {
                                    sp.next().map(|v| v.to_string())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_default();
                        out.push_str(&val);
                    } else {
                        out.push(c);
                    }
                }
                self.print(&format(format_args!("{out}\n")));
            }

            t if t.starts_with("export ") => {
                // export KEY=VAL
                if let Some(rest) = t.strip_prefix("export ") {
                    if let Some((k, v)) = rest.split_once('=') {
                        let pair = format(format_args!("{k}={v}"));
                        self.env.push(pair);
                    }
                }
            }

            t if t.starts_with('/') => {
                // build argv[]
                const MAX_ARGS: usize = 16;
                let mut argv: [*mut u8; MAX_ARGS + 1] = [core::ptr::null_mut(); MAX_ARGS + 1];
                let mut argc = 0;
                let mut start = 0;

                // split buffer on spaces
                for i in 0..=self.position {
                    if i == self.position || self.buffer[i] == b' ' {
                        self.buffer[i] = 0;
                        if argc < MAX_ARGS {
                            argv[argc] = unsafe { self.buffer.as_mut_ptr().add(start) };
                            argc += 1;
                        }
                        start = i + 1;
                    }
                }
                // end
                argv[argc] = core::ptr::null_mut();

                // build envp[]
                let mut envp: Vec<*mut u8> = self
                    .env
                    .iter_mut()
                    .map(|s| {
                        s.push('\0');
                        s.as_mut_ptr()
                    })
                    .collect();
                // end
                envp.push(core::ptr::null_mut());
                serial_println!("EXECUTING");
                unsafe {
                    spin_on(
                        // TODO use schedule_kernel
                        sys_exec(argv[0], argv.as_mut_ptr(), envp.as_mut_ptr()),
                    );
                }
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
pub unsafe fn init() {
    let shell = Shell::new();
    shell.run();
}
