use super::error::ProtocolError;
use super::messages::{MessageHeader, MessageType};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub struct MessageWriter {
    buf: BytesMut,
}

impl MessageWriter {
    pub fn new(initial_capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(initial_capacity),
        }
    }

    pub fn start_message(&mut self, msg_type: MessageType, tag: u16) {
        self.buf.put_u32(0);
        self.buf.put_u8(msg_type as u8);
        self.buf.put_u16(tag);
    }

    pub fn put_bytes(&mut self, bytes: &Bytes) -> Result<(), ProtocolError> {
        if bytes.len() > u16::MAX as usize {
            return Err(ProtocolError::MessageTooLarge);
        }
        self.buf.put_u16(bytes.len() as u16);
        self.buf.put_slice(bytes);
        Ok(())
    }

    pub fn put_u32(&mut self, val: u32) {
        self.buf.put_u32(val);
    }

    pub fn finish(mut self) -> Bytes {
        let size = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&size.to_be_bytes());
        self.buf.freeze()
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
            // 4 + 1 + 2
            return Err(ProtocolError::BufferTooSmall);
        }

        let size = self.buf.get_u32();
        let message_type = MessageType::try_from(self.buf.get_u8())?;
        let tag = self.buf.get_u16();

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
        let len = self.buf.get_u16() as usize;
        if len > self.buf.len() {
            return Err(ProtocolError::BufferTooSmall);
        }
        Ok(self.buf.split_to(len))
    }

    pub fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        if self.buf.len() < 4 {
            return Err(ProtocolError::BufferTooSmall);
        }
        Ok(self.buf.get_u32())
    }
}
