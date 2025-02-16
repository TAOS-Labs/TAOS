use super::error::ProtocolError;
use super::messages::{MessageHeader, MessageType, MAX_MESSAGE_SIZE};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub struct MessageWriter {
    buf: BytesMut,
}

impl MessageWriter {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    pub fn put_header(&mut self, msg_type: MessageType, tag: u16) -> Result<(), ProtocolError> {
        self.buf.put_u32_le(0);
        self.buf.put_u8(msg_type as u8);
        self.buf.put_u16_le(tag);
        Ok(())
    }

    pub fn put_bytes(&mut self, bytes: &Bytes) -> Result<(), ProtocolError> {
        if bytes.len() > u16::MAX as usize {
            return Err(ProtocolError::MessageTooLarge);
        }
        self.buf.put_u16_le(bytes.len() as u16);
        self.buf.put_slice(bytes);
        Ok(())
    }

    pub fn put_u32(&mut self, val: u32) -> Result<(), ProtocolError> {
        self.buf.put_u32_le(val);
        Ok(())
    }

    pub fn finish(mut self) -> Result<Bytes, ProtocolError> {
        let size = self.buf.len() as u32;
        if size > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::ExceedsMaxSize);
        }
        self.buf[0..4].copy_from_slice(&size.to_le_bytes());
        Ok(self.buf.freeze())
    }
}

pub struct MessageReader<'a> {
    buf: &'a mut Bytes,
}

impl<'a> MessageReader<'a> {
    pub fn new(buf: &'a mut Bytes) -> Self {
        Self { buf }
    }

    pub fn read_header(&mut self) -> Result<MessageHeader, ProtocolError> {
        if self.buf.len() < 7 {
            return Err(ProtocolError::BufferTooSmall);
        }

        let size = self.buf.get_u32_le();
        if size > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::ExceedsMaxSize);
        }

        let message_type = MessageType::try_from(self.buf.get_u8())?;
        let tag = self.buf.get_u16_le();

        Ok(MessageHeader {
            size,
            message_type,
            tag,
        })
    }

    pub fn read_bytes(&mut self) -> Result<Bytes, ProtocolError> {
        if self.buf.len() < 2 {
            return Err(ProtocolError::BufferTooSmall);
        }
        let len = self.buf.get_u16_le() as usize;
        if len > self.buf.len() {
            return Err(ProtocolError::BufferTooSmall);
        }
        Ok(self.buf.split_to(len))
    }

    pub fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        if self.buf.len() < 4 {
            return Err(ProtocolError::BufferTooSmall);
        }
        Ok(self.buf.get_u32_le())
    }
}
