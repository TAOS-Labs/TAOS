use super::serialization::{MessageReader, MessageWriter};
use super::{
    error::ProtocolError,
    messages::{MessageHeader, MessageType},
};
use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct Rversion {
    pub header: MessageHeader,
    pub msize: u32,
    pub version: Bytes,
}

#[derive(Debug, Clone)]
pub struct Rattach {
    pub header: MessageHeader,
    pub qid: Bytes,
}

impl Rversion {
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);

        let header = reader.read_header()?;
        let msize = reader.read_u32()?;
        let version = reader.read_bytes()?;

        Ok(Rversion {
            header,
            msize,
            version,
        })
    }

    pub fn serialize(&self) -> Bytes {
        let capacity = 4 + 1 + 2 + 4 + 2 + self.version.len();
        let mut writer = MessageWriter::new(capacity);

        writer.start_message(MessageType::Rversion, self.header.tag);
        writer.put_u32(self.msize);
        writer
            .put_bytes(&self.version)
            .expect("version bytes too long");

        writer.finish()
    }
}

impl Rattach {
    pub fn deserialize(mut bytes: Bytes) -> Result<Self, ProtocolError> {
        let mut reader = MessageReader::new(&mut bytes);

        let header = reader.read_header()?;
        let qid = reader.read_bytes()?;

        if qid.len() != 13 {
            return Err(ProtocolError::InvalidQid);
        }

        Ok(Rattach { header, qid })
    }

    pub fn serialize(&self) -> Bytes {
        let capacity = 4 + 1 + 2 + 2 + self.qid.len();
        let mut writer = MessageWriter::new(capacity);

        writer.start_message(MessageType::Rattach, self.header.tag);
        writer.put_bytes(&self.qid).expect("qid bytes too long");

        writer.finish()
    }
}
