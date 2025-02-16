use super::error::ProtocolError;
use super::messages::{MessageHeader, MessageType, MAX_MESSAGE_SIZE};
use super::serialization::{MessageReader, MessageWriter};
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq)]
pub struct Rversion {
    pub header: MessageHeader,
    pub msize: u32,
    pub version: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rattach {
    pub header: MessageHeader,
    pub qid: Bytes,
}

impl Rversion {
    pub fn new(tag: u16, msize: u32, version: Bytes) -> Result<Self, ProtocolError> {
        if version.len() > u16::MAX as usize {
            return Err(ProtocolError::VersionTooLong);
        }
        if msize > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::ExceedsMaxSize);
        }

        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rversion,
                tag,
            },
            msize,
            version,
        })
    }

    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.msize)?;
        writer.put_bytes(&self.version)?;
        writer.finish()
    }

    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rversion {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }

        let msize = reader.read_u32()?;
        let version = reader.read_bytes()?;

        if msize > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::ExceedsMaxSize);
        }

        Ok(Self {
            header,
            msize,
            version,
        })
    }
}

impl Rattach {
    pub fn new(tag: u16, qid: Bytes) -> Result<Self, ProtocolError> {
        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }

        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rattach,
                tag,
            },
            qid,
        })
    }

    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_bytes(&self.qid)?;
        writer.finish()
    }

    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rattach {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }

        let qid = reader.read_bytes()?;
        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }

        Ok(Self { header, qid })
    }
}
