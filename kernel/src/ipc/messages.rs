use super::{error::ProtocolError, requests, responses};
use bytes::{Buf, Bytes};
use core::convert::TryFrom;

pub const VERSION: &[u8] = b"9P2000";
pub const MAX_MESSAGE_SIZE: u32 = 8192;

#[derive(Debug, Clone, PartialEq)]
pub struct MessageHeader {
    pub size: u32,
    pub message_type: MessageType,
    pub tag: u16,
}

impl MessageHeader {
    pub fn from_bytes(mut bytes: Bytes) -> Result<(Self, Bytes), ProtocolError> {
        if bytes.len() < 7 {
            return Err(ProtocolError::InvalidDataLength);
        }

        // Parse size (4 bytes, little-endian)
        let size = bytes.get_u32_le();

        // Parse message type (1 byte)
        let message_type = MessageType::try_from(bytes.get_u8())?;

        // Parse tag (2 bytes, little-endian)
        let tag = bytes.get_u16_le();

        Ok((
            MessageHeader {
                size,
                message_type,
                tag,
            },
            bytes,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    Terror = 106,
    Rerror = 107,
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Topen = 112,
    Ropen = 113,
    Tcreate = 114,
    Rcreate = 115,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tremove = 122,
    Rremove = 123,
    Tstat = 124,
    Rstat = 125,
    Twstat = 126,
    Rwstat = 127,
}

impl MessageType {
    pub fn response_type(&self) -> Self {
        match *self {
            MessageType::Tversion => MessageType::Rversion,
            MessageType::Tauth => MessageType::Rauth,
            MessageType::Tattach => MessageType::Rattach,
            MessageType::Tflush => MessageType::Rflush,
            MessageType::Twalk => MessageType::Rwalk,
            MessageType::Topen => MessageType::Ropen,
            MessageType::Tcreate => MessageType::Rcreate,
            MessageType::Tread => MessageType::Rread,
            MessageType::Twrite => MessageType::Rwrite,
            MessageType::Tclunk => MessageType::Rclunk,
            MessageType::Tremove => MessageType::Rremove,
            MessageType::Tstat => MessageType::Rstat,
            MessageType::Twstat => MessageType::Rwstat,
            _ => MessageType::Rerror,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(MessageType::Tversion),
            101 => Ok(MessageType::Rversion),
            102 => Ok(MessageType::Tauth),
            103 => Ok(MessageType::Rauth),
            104 => Ok(MessageType::Tattach),
            105 => Ok(MessageType::Rattach),
            106 => Ok(MessageType::Terror),
            107 => Ok(MessageType::Rerror),
            108 => Ok(MessageType::Tflush),
            109 => Ok(MessageType::Rflush),
            110 => Ok(MessageType::Twalk),
            111 => Ok(MessageType::Rwalk),
            112 => Ok(MessageType::Topen),
            113 => Ok(MessageType::Ropen),
            114 => Ok(MessageType::Tcreate),
            115 => Ok(MessageType::Rcreate),
            116 => Ok(MessageType::Tread),
            117 => Ok(MessageType::Rread),
            118 => Ok(MessageType::Twrite),
            119 => Ok(MessageType::Rwrite),
            120 => Ok(MessageType::Tclunk),
            121 => Ok(MessageType::Rclunk),
            122 => Ok(MessageType::Tremove),
            123 => Ok(MessageType::Rremove),
            124 => Ok(MessageType::Tstat),
            125 => Ok(MessageType::Rstat),
            126 => Ok(MessageType::Twstat),
            127 => Ok(MessageType::Rwstat),
            invalid => Err(ProtocolError::InvalidMessageType(invalid)),
        }
    }
}

#[derive(Debug)]
pub enum Message {
    // Version negotiation
    Tversion(requests::Tversion),
    Rversion(responses::Rversion),

    // Authentication
    Tauth(requests::Tauth),
    Rauth(responses::Rauth),

    // Connection establishment
    Tattach(requests::Tattach),
    Rattach(responses::Rattach),

    // Error response (only R message, no T message)
    Rerror(responses::Rerror),

    // File walking
    Twalk(requests::Twalk),
    Rwalk(responses::Rwalk),

    // Open/Create operations
    Topen(requests::Topen),
    Ropen(responses::Ropen),
    Tcreate(requests::Tcreate),
    Rcreate(responses::Rcreate),

    // I/O operations
    Tread(requests::Tread),
    Rread(responses::Rread),
    Twrite(requests::Twrite),
    Rwrite(responses::Rwrite),

    // File manipulation
    Tclunk(requests::Tclunk),
    Rclunk(responses::Rclunk),
    Tremove(requests::Tremove),
    Rremove(responses::Rremove),

    // File/Directory stats
    Tstat(requests::Tstat),
    Rstat(responses::Rstat),
    Twstat(requests::Twstat),
    Rwstat(responses::Rwstat),

    // Flush pending operations
    Tflush(requests::Tflush),
    Rflush(responses::Rflush),
}

impl Message {
    pub fn from_bytes(header: MessageHeader, data: Bytes) -> Result<Self, ProtocolError> {
        match header.message_type {
            MessageType::Tversion => Ok(Message::Tversion(requests::Tversion::deserialize(data)?)),
            MessageType::Rversion => Ok(Message::Rversion(responses::Rversion::deserialize(data)?)),

            MessageType::Tauth => Ok(Message::Tauth(requests::Tauth::deserialize(data)?)),
            MessageType::Rauth => Ok(Message::Rauth(responses::Rauth::deserialize(data)?)),

            MessageType::Tattach => Ok(Message::Tattach(requests::Tattach::deserialize(data)?)),
            MessageType::Rattach => Ok(Message::Rattach(responses::Rattach::deserialize(data)?)),

            MessageType::Rerror => Ok(Message::Rerror(responses::Rerror::deserialize(data)?)),

            MessageType::Twalk => Ok(Message::Twalk(requests::Twalk::deserialize(data)?)),
            MessageType::Rwalk => Ok(Message::Rwalk(responses::Rwalk::deserialize(data)?)),

            MessageType::Topen => Ok(Message::Topen(requests::Topen::deserialize(data)?)),
            MessageType::Ropen => Ok(Message::Ropen(responses::Ropen::deserialize(data)?)),

            MessageType::Tcreate => Ok(Message::Tcreate(requests::Tcreate::deserialize(data)?)),
            MessageType::Rcreate => Ok(Message::Rcreate(responses::Rcreate::deserialize(data)?)),

            MessageType::Tread => Ok(Message::Tread(requests::Tread::deserialize(data)?)),
            MessageType::Rread => Ok(Message::Rread(responses::Rread::deserialize(data)?)),

            MessageType::Twrite => Ok(Message::Twrite(requests::Twrite::deserialize(data)?)),
            MessageType::Rwrite => Ok(Message::Rwrite(responses::Rwrite::deserialize(data)?)),

            MessageType::Tclunk => Ok(Message::Tclunk(requests::Tclunk::deserialize(data)?)),
            MessageType::Rclunk => Ok(Message::Rclunk(responses::Rclunk::deserialize(data)?)),

            MessageType::Tremove => Ok(Message::Tremove(requests::Tremove::deserialize(data)?)),
            MessageType::Rremove => Ok(Message::Rremove(responses::Rremove::deserialize(data)?)),

            MessageType::Tstat => Ok(Message::Tstat(requests::Tstat::deserialize(data)?)),
            MessageType::Rstat => Ok(Message::Rstat(responses::Rstat::deserialize(data)?)),

            MessageType::Twstat => Ok(Message::Twstat(requests::Twstat::deserialize(data)?)),
            MessageType::Rwstat => Ok(Message::Rwstat(responses::Rwstat::deserialize(data)?)),

            MessageType::Tflush => Ok(Message::Tflush(requests::Tflush::deserialize(data)?)),
            MessageType::Rflush => Ok(Message::Rflush(responses::Rflush::deserialize(data)?)),

            // Terror shouldn't be received
            MessageType::Terror => {
                Err(ProtocolError::InvalidMessageType(MessageType::Terror as u8))
            }
        }
    }

    pub fn parse(bytes: Bytes) -> Result<(Self, u16), ProtocolError> {
        let (header, remaining) = MessageHeader::from_bytes(bytes)?;
        let tag = header.tag;

        if header.size as usize != remaining.len() + 7 {
            return Err(ProtocolError::InvalidDataLength);
        }

        // Size should never exceed MAX_MESSAGE_SIZE
        if header.size > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge);
        }

        let message = Self::from_bytes(header, remaining)?;
        Ok((message, tag))
    }

    pub fn serialize(&self) -> Result<Bytes, ProtocolError> {
        match self {
            Message::Tversion(m) => m.serialize(),
            Message::Rversion(m) => m.serialize(),
            Message::Tauth(m) => m.serialize(),
            Message::Rauth(m) => m.serialize(),
            Message::Tattach(m) => m.serialize(),
            Message::Rattach(m) => m.serialize(),
            Message::Rerror(m) => m.serialize(),
            Message::Twalk(m) => m.serialize(),
            Message::Rwalk(m) => m.serialize(),
            Message::Topen(m) => m.serialize(),
            Message::Ropen(m) => m.serialize(),
            Message::Tcreate(m) => m.serialize(),
            Message::Rcreate(m) => m.serialize(),
            Message::Tread(m) => m.serialize(),
            Message::Rread(m) => m.serialize(),
            Message::Twrite(m) => m.serialize(),
            Message::Rwrite(m) => m.serialize(),
            Message::Tclunk(m) => m.serialize(),
            Message::Rclunk(m) => m.serialize(),
            Message::Tremove(m) => m.serialize(),
            Message::Rremove(m) => m.serialize(),
            Message::Tstat(m) => m.serialize(),
            Message::Rstat(m) => m.serialize(),
            Message::Twstat(m) => m.serialize(),
            Message::Rwstat(m) => m.serialize(),
            Message::Tflush(m) => m.serialize(),
            Message::Rflush(m) => m.serialize(),
        }
    }
}
