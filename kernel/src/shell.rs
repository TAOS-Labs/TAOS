use alloc::{
    fmt::format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    devices::ps2_dev::keyboard,
    events::schedule_kernel,
    serial_println,
    syscalls::syscall_handlers::{event_to_ascii, sys_exec, sys_write},
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
        schedule_kernel(
            async move {
                let mut shell = self;
                loop {
                    let c = shell.read_char().await;
                    match c {
                        b'\n' | b'\r' => {
                            shell.execute_command().await;
                            keyboard::flush_buffer();
                            shell.print_prompt();
                            serial_println!("ENVS: {:#?}", shell.env);
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

    async fn read_char(&mut self) -> u8 {
        // Wait for the next keypress that maps to ASCII. next_event() pends
        // and yields to the scheduler while idle instead of busy-spinning.
        let c = loop {
            let event = keyboard::next_event().await;
            if let Some(c) = event_to_ascii(&event) {
                break c;
            }
        };
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
        unsafe { sys_write(1, s.as_ptr() as *mut u8, s.len()) };
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
                self.print(&format(format_args!("{}\n", out)));
            }

            t if t.starts_with("export ") => {
                // export KEY=VAL; replace the existing entry if the key
                // already exists instead of accumulating duplicates
                if let Some(rest) = t.strip_prefix("export ") {
                    if let Some((k, v)) = rest.split_once('=') {
                        let pair = format(format_args!("{}={}", k, v));
                        if let Some(existing) = self
                            .env
                            .iter_mut()
                            .find(|kv| kv.splitn(2, '=').next() == Some(k))
                        {
                            *existing = pair;
                        } else {
                            self.env.push(pair);
                        }
                    }
                }
            }

            t if t.starts_with('/') => {
                // build argv[]
                const MAX_ARGS: usize = 16;
                let mut argv: [*mut u8; MAX_ARGS + 1] = [core::ptr::null_mut(); MAX_ARGS + 1];
                let mut argc = 0;
                let mut start = 0;

                // split buffer on spaces, skipping empty segments so that
                // consecutive spaces don't produce empty arguments
                for i in 0..=self.position {
                    if i == self.position || self.buffer[i] == b' ' {
                        self.buffer[i] = 0;
                        if start < i && argc < MAX_ARGS {
                            argv[argc] = unsafe { self.buffer.as_mut_ptr().add(start) };
                            argc += 1;
                        }
                        start = i + 1;
                    }
                }
                // end
                argv[argc] = core::ptr::null_mut();

                // build envp[] from temporary NUL-terminated copies; the
                // shell's persistent environment strings are never mutated
                let env_strings: Vec<String> = self
                    .env
                    .iter()
                    .map(|kv| format(format_args!("{}\0", kv)))
                    .collect();
                let mut envp: Vec<*mut u8> = env_strings
                    .iter()
                    .map(|kv| kv.as_ptr() as *mut u8)
                    .collect();
                // end
                envp.push(core::ptr::null_mut());
                serial_println!("EXECUTING");
                unsafe {
                    sys_exec(argv[0], argv.as_mut_ptr(), envp.as_mut_ptr());
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
    keyboard::flush_buffer();
    let shell = Shell::new();
    shell.run();
}
