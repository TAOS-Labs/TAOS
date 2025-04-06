use alloc::string::String;

// Todo: Make this a better error type
#[derive(Debug)]
pub enum TaskError {
    Cancelled,
    Timeout,
    ExecutionError(String),
}
