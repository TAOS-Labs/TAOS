#[derive(Debug)]
pub enum ProtocolError {
    MessageTooLarge,
    InvalidMessageType(u8),
    BufferTooSmall,
    InvalidQid,
    VersionTooLong,
    UsernameTooLong,
    AnameTooLong,
    ExceedsMaxSize,
    FilenameTooLong,
    InvalidDataLength,
    ErrorTooLong,
}

impl From<u8> for ProtocolError {
    fn from(value: u8) -> Self {
        ProtocolError::InvalidMessageType(value)
    }
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtocolError::MessageTooLarge => write!(f, "Message too large"),
            ProtocolError::InvalidMessageType(t) => write!(f, "Invalid message type: {}", t),
            ProtocolError::BufferTooSmall => write!(f, "Buffer too small"),
            ProtocolError::InvalidQid => write!(f, "Invalid Qid size (must be 13 bytes)"),
            ProtocolError::VersionTooLong => write!(f, "Version string too long"),
            ProtocolError::UsernameTooLong => write!(f, "Username too long"),
            ProtocolError::AnameTooLong => write!(f, "Aname too long"),
            ProtocolError::ExceedsMaxSize => write!(f, "Message size exceeds maximum"),
            ProtocolError::FilenameTooLong => write!(f, "Filename is too long"),
            ProtocolError::InvalidDataLength => write!(f, "Invalid data length"),
            ProtocolError::ErrorTooLong => write!(f, "Requested error message too long"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    NoMount,
    InvalidMount,
    ChannelFull,
    NoResponse,
    Protocol,
    BadFileDescriptor,
    InvalidPath,
    TooManyComponents,
    NotFound,
    AlreadyMounted,
    NotMount,
}
