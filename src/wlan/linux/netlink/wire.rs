use std::io;

pub(super) const NLM_F_REQUEST: u16 = 0x0001;
pub(super) const NLM_F_ACK: u16 = 0x0004;
pub(super) const NLM_F_DUMP: u16 = 0x0300;
const NLMSG_ERROR: u16 = 0x0002;
const NLMSG_DONE: u16 = 0x0003;
pub(super) const GENL_ID_CTRL: u16 = 0x0010;

pub(super) const CTRL_CMD_GETFAMILY: u8 = 3;
pub(super) const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub(super) const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub(super) const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

const NLA_TYPE_MASK: u16 = 0x3fff;
pub(crate) struct Message {
    #[cfg_attr(not(feature = "scan"), allow(dead_code))]
    pub command: u8,
    pub attributes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Attribute<'a> {
    pub kind: u16,
    pub value: &'a [u8],
}

pub(super) struct ParsedDatagram {
    pub(super) messages: Vec<Message>,
    pub(super) acknowledged: bool,
    pub(super) done: bool,
}
pub(super) fn packet(family: u16, flags: u16, sequence: u32, command: u8, attrs: &[u8]) -> Vec<u8> {
    let length = 16 + 4 + attrs.len();
    let mut out = Vec::with_capacity(align4(length));
    out.extend_from_slice(&(length as u32).to_ne_bytes());
    out.extend_from_slice(&family.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.push(command);
    out.push(1); // generic netlink family version
    out.extend_from_slice(&0u16.to_ne_bytes());
    out.extend_from_slice(attrs);
    out.resize(align4(length), 0);
    out
}

pub(super) fn parse_datagram(bytes: &[u8], sequence: Option<u32>) -> io::Result<ParsedDatagram> {
    let mut messages = Vec::new();
    let mut acknowledged = false;
    let mut done = false;
    let mut offset = 0usize;

    while offset + 16 <= bytes.len() {
        let length = read_u32(&bytes[offset..]).unwrap_or(0) as usize;
        if length < 16 || offset + length > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netlink message length",
            ));
        }
        let message_type = read_u16(&bytes[offset + 4..]).unwrap_or(0);
        let message_sequence = read_u32(&bytes[offset + 8..]).unwrap_or(0);
        if sequence.is_some_and(|expected| expected != message_sequence) {
            offset += align4(length);
            continue;
        }

        let payload = &bytes[offset + 16..offset + length];
        match message_type {
            NLMSG_ERROR => {
                let code = payload
                    .get(..4)
                    .and_then(read_i32)
                    .ok_or_else(|| io::Error::other("truncated netlink error"))?;
                if code == 0 {
                    acknowledged = true;
                } else {
                    return Err(io::Error::from_raw_os_error(code.saturating_neg()));
                }
            }
            NLMSG_DONE => done = true,
            _ if payload.len() >= 4 => messages.push(Message {
                command: payload[0],
                attributes: payload[4..].to_vec(),
            }),
            _ => {}
        }

        offset += align4(length);
    }

    Ok(ParsedDatagram {
        messages,
        acknowledged,
        done,
    })
}

pub(crate) fn attributes(bytes: &[u8]) -> Vec<Attribute<'_>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let length = read_u16(&bytes[offset..]).unwrap_or(0) as usize;
        if length < 4 || offset + length > bytes.len() {
            break;
        }
        let kind = read_u16(&bytes[offset + 2..]).unwrap_or(0) & NLA_TYPE_MASK;
        out.push(Attribute {
            kind,
            value: &bytes[offset + 4..offset + length],
        });
        offset += align4(length);
    }
    out
}

pub(crate) fn push_attribute(target: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = 4 + value.len();
    target.extend_from_slice(&(length as u16).to_ne_bytes());
    target.extend_from_slice(&kind.to_ne_bytes());
    target.extend_from_slice(value);
    target.resize(align4(target.len()), 0);
}

pub(crate) fn push_u32(target: &mut Vec<u8>, kind: u16, value: u32) {
    push_attribute(target, kind, &value.to_ne_bytes());
}

pub(crate) fn read_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?))
}

pub(crate) fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

pub(crate) fn read_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?))
}

fn read_i32(bytes: &[u8]) -> Option<i32> {
    Some(i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

pub(super) fn multicast_group(bytes: &[u8], expected: &str) -> Option<u32> {
    for group in attributes(bytes) {
        let mut name = None;
        let mut id = None;
        for field in attributes(group.value) {
            match field.kind {
                CTRL_ATTR_MCAST_GRP_NAME => {
                    name =
                        std::str::from_utf8(field.value.strip_suffix(&[0]).unwrap_or(field.value))
                            .ok();
                }
                CTRL_ATTR_MCAST_GRP_ID => id = read_u32(field.value),
                _ => {}
            }
        }
        if name == Some(expected) {
            return id;
        }
    }
    None
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}
