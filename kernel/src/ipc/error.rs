#[derive(Debug)]
pub enum ProtocolError {
    MessageTooLarge,
    InvalidMessageType,
    BufferTooSmall,
    InvalidQid,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtocolError::MessageTooLarge => write!(f, "Message too large"),
            ProtocolError::InvalidMessageType => write!(f, "Invalid message type"),
            ProtocolError::BufferTooSmall => write!(f, "Buffer too small"),
            ProtocolError::InvalidQid => write!(f, "Invalid Qid size (must be 13 bytes)"),
        }
    }
}
