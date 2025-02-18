use super::error::ProtocolError;
use super::messages::{MessageHeader, MessageType, MAX_MESSAGE_SIZE};
use super::serialization::{MessageReader, MessageWriter};
use alloc::vec::Vec;
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq)]
pub struct Rversion {
    pub header: MessageHeader,
    pub msize: u32,
    pub version: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rauth {
    pub header: MessageHeader,
    pub qid: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rattach {
    pub header: MessageHeader,
    pub qid: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rerror {
    pub header: MessageHeader,
    pub ename: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rflush {
    pub header: MessageHeader,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rwalk {
    pub header: MessageHeader,
    pub wqid: Vec<Bytes>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ropen {
    pub header: MessageHeader,
    pub qid: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rcreate {
    pub header: MessageHeader,
    pub qid: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rread {
    pub header: MessageHeader,
    pub count: u32,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rwrite {
    pub header: MessageHeader,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rclunk {
    pub header: MessageHeader,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rremove {
    pub header: MessageHeader,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rstat {
    pub header: MessageHeader,
    pub stat: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rwstat {
    pub header: MessageHeader,
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

impl Rauth {
    pub fn new(tag: u16, qid: Bytes) -> Result<Self, ProtocolError> {
        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rauth,
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
        if header.message_type != MessageType::Rauth {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let qid = reader.read_bytes()?;
        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }
        Ok(Self { header, qid })
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

impl Rerror {
    pub fn new(tag: u16, ename: Bytes) -> Result<Self, ProtocolError> {
        if ename.len() > u16::MAX as usize {
            return Err(ProtocolError::ErrorTooLong);
        }
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rerror,
                tag,
            },
            ename,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_bytes(&self.ename)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rerror {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let ename = reader.read_bytes()?;
        Ok(Self { header, ename })
    }
}

impl Rflush {
    pub fn new(tag: u16) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rflush,
                tag,
            },
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rflush {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        Ok(Self { header })
    }
}

impl Rwalk {
    pub fn new(tag: u16, wqid: Vec<Bytes>) -> Result<Self, ProtocolError> {
        for qid in &wqid {
            if qid.len() != 13 {
                return Err(ProtocolError::InvalidQid);
            }
        }
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rwalk,
                tag,
            },
            wqid,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u16(self.wqid.len() as u16)?;
        for qid in &self.wqid {
            writer.put_bytes(qid)?;
        }
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rwalk {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let count = reader.read_u16()? as usize;
        let mut wqid = Vec::with_capacity(count);
        for _ in 0..count {
            let q = reader.read_bytes()?;
            if q.len() != 13 {
                return Err(ProtocolError::InvalidQid);
            }
            wqid.push(q);
        }
        Ok(Self { header, wqid })
    }
}

impl Ropen {
    pub fn new(tag: u16, qid: Bytes) -> Result<Self, ProtocolError> {
        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Ropen,
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
        if header.message_type != MessageType::Ropen {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let qid = reader.read_bytes()?;
        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }
        Ok(Self { header, qid })
    }
}

impl Rcreate {
    pub fn new(tag: u16, qid: Bytes) -> Result<Self, ProtocolError> {
        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rcreate,
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
        if header.message_type != MessageType::Rcreate {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let qid = reader.read_bytes()?;
        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }
        Ok(Self { header, qid })
    }
}

impl Rread {
    pub fn new(tag: u16, data: Bytes) -> Result<Self, ProtocolError> {
        if data.len() > u32::MAX as usize {
            return Err(ProtocolError::InvalidDataLength);
        }

        let count: u32 = data.len() as u32;
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rread,
                tag,
            },
            count,
            data,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.count)?;
        writer.put_bytes(&self.data)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rread {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let count = reader.read_u32()?;
        let data = reader.read_bytes()?;
        Ok(Self {
            header,
            count,
            data,
        })
    }
}

impl Rwrite {
    pub fn new(tag: u16, count: u32) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rwrite,
                tag,
            },
            count,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.count)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rwrite {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let count = reader.read_u32()?;
        Ok(Self { header, count })
    }
}

impl Rclunk {
    pub fn new(tag: u16) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rclunk,
                tag,
            },
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rclunk {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        Ok(Self { header })
    }
}

impl Rremove {
    pub fn new(tag: u16) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rremove,
                tag,
            },
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rremove {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        Ok(Self { header })
    }
}

impl Rstat {
    pub fn new(tag: u16, stat: Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rstat,
                tag,
            },
            stat,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_bytes(&self.stat)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rstat {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let stat = reader.read_bytes()?;
        Ok(Self { header, stat })
    }
}

impl Rwstat {
    pub fn new(tag: u16) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Rwstat,
                tag,
            },
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Rwstat {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        Ok(Self { header })
    }
}
