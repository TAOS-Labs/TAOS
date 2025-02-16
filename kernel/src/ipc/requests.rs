use super::error::ProtocolError;
use super::messages::{MessageHeader, MessageType, MAX_MESSAGE_SIZE};
use super::serialization::{MessageReader, MessageWriter};
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq)]
pub struct Tversion {
    pub header: MessageHeader,
    pub msize: u32,
    pub version: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tattach {
    pub header: MessageHeader,
    pub fid: u32,
    pub afid: u32,
    pub uname: Bytes,
    pub aname: Bytes,
}

impl Tversion {
    pub fn new(tag: u16, msize: u32, version: Bytes) -> Result<Self, ProtocolError> {
        if version.len() > u16::MAX as usize {
            return Err(ProtocolError::VersionTooLong);
        }
        if msize > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::ExceedsMaxSize);
        }

        Ok(Self {
            header: MessageHeader {
                size: 0, // Will be set during serialization
                message_type: MessageType::Tversion,
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
        if header.message_type != MessageType::Tversion {
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

impl Tattach {
    pub fn new(
        tag: u16,
        fid: u32,
        afid: u32,
        uname: Bytes,
        aname: Bytes,
    ) -> Result<Self, ProtocolError> {
        if uname.len() > u16::MAX as usize {
            return Err(ProtocolError::UsernameTooLong);
        }
        if aname.len() > u16::MAX as usize {
            return Err(ProtocolError::AnameTooLong);
        }

        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Tattach,
                tag,
            },
            fid,
            afid,
            uname,
            aname,
        })
    }

    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.put_u32(self.afid)?;
        writer.put_bytes(&self.uname)?;
        writer.put_bytes(&self.aname)?;
        writer.finish()
    }

    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Tattach {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }

        let fid = reader.read_u32()?;
        let afid = reader.read_u32()?;
        let uname = reader.read_bytes()?;
        let aname = reader.read_bytes()?;

        Ok(Self {
            header,
            fid,
            afid,
            uname,
            aname,
        })
    }
}
