use super::{
    error::ProtocolError,
    messages::{MessageHeader, MessageType, MAX_MESSAGE_SIZE},
    serialization::{MessageReader, MessageWriter},
};
use alloc::vec::Vec;
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq)]
pub struct Tversion {
    pub header: MessageHeader,
    pub msize: u32,
    pub version: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tauth {
    pub header: MessageHeader,
    pub afid: u32,
    pub uname: Bytes,
    pub aname: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tflush {
    pub header: MessageHeader,
    pub oldtag: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tattach {
    pub header: MessageHeader,
    pub fid: u32,
    pub afid: u32,
    pub uname: Bytes,
    pub aname: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Twalk {
    pub header: MessageHeader,
    pub fid: u32,
    pub newfid: u32,
    pub wnames: Vec<Bytes>, // Sequence of path components, get nwnames from this
}

#[derive(Debug, Clone, PartialEq)]
pub struct Topen {
    pub header: MessageHeader,
    pub fid: u32,
    pub mode: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tcreate {
    pub header: MessageHeader,
    pub fid: u32,
    pub name: Bytes,
    pub perm: u32,
    pub mode: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tread {
    pub header: MessageHeader,
    pub fid: u32,
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Twrite {
    pub header: MessageHeader,
    pub fid: u32,
    pub offset: u64,
    pub count: u32,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tclunk {
    pub header: MessageHeader,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tremove {
    pub header: MessageHeader,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tstat {
    pub header: MessageHeader,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Twstat {
    pub header: MessageHeader,
    pub fid: u32,
    pub stat: Bytes,
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

impl Tauth {
    pub fn new(tag: u16, afid: u32, uname: Bytes, aname: Bytes) -> Result<Self, ProtocolError> {
        if uname.len() > u16::MAX as usize {
            return Err(ProtocolError::UsernameTooLong);
        }
        if aname.len() > u16::MAX as usize {
            return Err(ProtocolError::AnameTooLong);
        }

        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Tauth,
                tag,
            },
            afid,
            uname,
            aname,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.afid)?;
        writer.put_bytes(&self.uname)?;
        writer.put_bytes(&self.aname)?;

        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Tauth {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let afid = reader.read_u32()?;
        let uname = reader.read_bytes()?;
        let aname = reader.read_bytes()?;
        Ok(Self {
            header,
            afid,
            uname,
            aname,
        })
    }
}

impl Tflush {
    pub fn new(tag: u16, oldtag: u16) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Tflush,
                tag,
            },
            oldtag,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u16(self.oldtag)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Tflush {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let oldtag = reader.read_u16()?;
        Ok(Self { header, oldtag })
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

impl Twalk {
    pub fn new(tag: u16, fid: u32, newfid: u32, wnames: Vec<Bytes>) -> Result<Self, ProtocolError> {
        if wnames.len() > u16::MAX as usize {
            return Err(ProtocolError::InvalidDataLength);
        }
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Twalk,
                tag,
            },
            fid,
            newfid,
            wnames,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.put_u32(self.newfid)?;
        writer.put_u16(self.wnames.len() as u16)?;
        for name in &self.wnames {
            writer.put_bytes(name)?;
        }
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Twalk {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        let newfid = reader.read_u32()?;
        let count = reader.read_u16()? as usize;
        let mut wnames = Vec::with_capacity(count);
        for _ in 0..count {
            let name = reader.read_bytes()?;
            wnames.push(name);
        }
        Ok(Self {
            header,
            fid,
            newfid,
            wnames,
        })
    }
}

impl Topen {
    pub fn new(tag: u16, fid: u32, mode: u8) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Topen,
                tag,
            },
            fid,
            mode,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.put_u8(self.mode)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Topen {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        let mode = reader.read_u8()?;
        Ok(Self { header, fid, mode })
    }
}

impl Tcreate {
    pub fn new(
        tag: u16,
        fid: u32,
        name: Bytes,
        perm: u32,
        mode: u8,
    ) -> Result<Self, ProtocolError> {
        if name.len() > u16::MAX as usize {
            return Err(ProtocolError::FilenameTooLong);
        }
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Tcreate,
                tag,
            },
            fid,
            name,
            perm,
            mode,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.put_bytes(&self.name)?;
        writer.put_u32(self.perm)?;
        writer.put_u8(self.mode)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Tcreate {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        let name = reader.read_bytes()?;
        let perm = reader.read_u32()?;
        let mode = reader.read_u8()?;
        Ok(Self {
            header,
            fid,
            name,
            perm,
            mode,
        })
    }
}

impl Tread {
    pub fn new(tag: u16, fid: u32, offset: u64, count: u32) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Tread,
                tag,
            },
            fid,
            offset,
            count,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.put_u64(self.offset)?;
        writer.put_u32(self.count)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Tread {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        let offset = reader.read_u64()?;
        let count = reader.read_u32()?;
        Ok(Self {
            header,
            fid,
            offset,
            count,
        })
    }
}

impl Twrite {
    pub fn new(tag: u16, fid: u32, offset: u64, data: Bytes) -> Result<Self, ProtocolError> {
        if data.len() > u32::MAX as usize {
            return Err(ProtocolError::InvalidDataLength);
        }

        let count = data.len() as u32;
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Twrite,
                tag,
            },
            fid,
            offset,
            count,
            data,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.put_u64(self.offset)?;
        writer.put_u32(self.count)?;
        writer.put_bytes(&self.data)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Twrite {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        let offset = reader.read_u64()?;
        let count = reader.read_u32()?;
        let data = reader.read_bytes()?;
        if data.len() != count as usize {
            return Err(ProtocolError::InvalidDataLength);
        }
        Ok(Self {
            header,
            fid,
            offset,
            count,
            data,
        })
    }
}

impl Tclunk {
    pub fn new(tag: u16, fid: u32) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Tclunk,
                tag,
            },
            fid,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Tclunk {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        Ok(Self { header, fid })
    }
}

impl Tremove {
    pub fn new(tag: u16, fid: u32) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Tremove,
                tag,
            },
            fid,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Tremove {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        Ok(Self { header, fid })
    }
}

impl Tstat {
    pub fn new(tag: u16, fid: u32) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Tstat,
                tag,
            },
            fid,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Tstat {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        Ok(Self { header, fid })
    }
}

impl Twstat {
    pub fn new(tag: u16, fid: u32, stat: Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            header: MessageHeader {
                size: 0,
                message_type: MessageType::Twstat,
                tag,
            },
            fid,
            stat,
        })
    }
    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        let mut writer = MessageWriter::new();
        writer.put_header(self.header.message_type, self.header.tag)?;
        writer.put_u32(self.fid)?;
        writer.put_bytes(&self.stat)?;
        writer.finish()
    }
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);
        let header = reader.read_header()?;
        if header.message_type != MessageType::Twstat {
            return Err(ProtocolError::InvalidMessageType(header.message_type as u8));
        }
        let fid = reader.read_u32()?;
        let stat = reader.read_bytes()?;
        Ok(Self { header, fid, stat })
    }
}
