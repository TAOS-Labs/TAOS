use super::error::ProtocolError;
use super::messages::{MessageHeader, MessageType};
use super::serialization::{MessageReader, MessageWriter};
use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct Tversion {
    pub header: MessageHeader,
    pub msize: u32,
    pub version: Bytes,
}

#[derive(Debug, Clone)]
pub struct Tattach {
    pub header: MessageHeader,
    pub fid: u32,
    pub afid: u32,
    pub uname: Bytes,
    pub aname: Bytes,
}

impl Tversion {
    pub fn serialize(&self) -> Bytes {
        let capacity = 4 + 1 + 2 + 4 + 2 + self.version.len();
        let mut writer = MessageWriter::new(capacity);

        writer.start_message(MessageType::Tversion, self.header.tag);
        writer.put_u32(self.msize);
        writer
            .put_bytes(&self.version)
            .expect("version bytes too long");

        writer.finish()
    }

    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);

        let header = reader.read_header()?;
        let msize = reader.read_u32()?;
        let version = reader.read_bytes()?;

        Ok(Tversion {
            header,
            msize,
            version,
        })
    }
}

impl Tattach {
    pub fn serialize(&self) -> Bytes {
        let capacity = 4 + 1 + 2 + 4 + 4 + 2 + self.uname.len() + 2 + self.aname.len();
        let mut writer = MessageWriter::new(capacity);

        writer.start_message(MessageType::Tattach, self.header.tag);
        writer.put_u32(self.fid);
        writer.put_u32(self.afid);
        writer.put_bytes(&self.uname).expect("uname bytes too long");
        writer.put_bytes(&self.aname).expect("aname bytes too long");

        writer.finish()
    }

    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);

        let header = reader.read_header()?;
        let fid = reader.read_u32()?;
        let afid = reader.read_u32()?;
        let uname = reader.read_bytes()?;
        let aname = reader.read_bytes()?;

        Ok(Tattach {
            header,
            fid,
            afid,
            uname,
            aname,
        })
    }
}
