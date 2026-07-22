//! Minimal Generic Netlink transport for `nl80211`.
//!
//! Only the stable userspace ABI used by the collector is represented here.
//! Keeping this module private prevents raw numeric attributes from leaking
//! into RadioChron's public API.

use std::ffi::c_void;
use std::io;
use std::os::raw::{c_int, c_short};
use std::time::Duration;

const AF_NETLINK: c_int = 16;
const SOCK_RAW: c_int = 3;
const NETLINK_GENERIC: c_int = 16;
const SOL_NETLINK: c_int = 270;
const NETLINK_ADD_MEMBERSHIP: c_int = 1;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_DUMP: u16 = 0x0300;
const NLMSG_ERROR: u16 = 0x0002;
const NLMSG_DONE: u16 = 0x0003;
const GENL_ID_CTRL: u16 = 0x0010;

const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

const NLA_TYPE_MASK: u16 = 0x3fff;
const POLLIN: c_short = 0x0001;

#[repr(C)]
struct SockAddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

extern "C" {
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, address: *const SockAddrNl, length: u32) -> c_int;
    fn sendto(
        fd: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const SockAddrNl,
        address_length: u32,
    ) -> isize;
    fn recv(fd: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        option: c_int,
        value: *const c_void,
        length: u32,
    ) -> c_int;
    fn poll(fds: *mut PollFd, count: usize, timeout_ms: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

#[derive(Debug, Clone)]
pub(super) struct Message {
    pub command: u8,
    pub attributes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Attribute<'a> {
    pub kind: u16,
    pub value: &'a [u8],
}

pub(super) struct GenericSocket {
    fd: c_int,
    family_id: u16,
    scan_group: Option<u32>,
    sequence: u32,
}

impl GenericSocket {
    pub fn open() -> io::Result<Self> {
        let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let address = SockAddrNl {
            family: AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        if unsafe { bind(fd, &address, std::mem::size_of::<SockAddrNl>() as u32) } < 0 {
            let error = io::Error::last_os_error();
            unsafe { close(fd) };
            return Err(error);
        }

        let mut socket = Self {
            fd,
            family_id: GENL_ID_CTRL,
            scan_group: None,
            sequence: 1,
        };
        let mut request = Vec::new();
        push_attribute(&mut request, CTRL_ATTR_FAMILY_NAME, b"nl80211\0");
        let replies = socket.transact_to(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, request, false)?;
        let reply = replies
            .first()
            .ok_or_else(|| io::Error::other("generic netlink returned no nl80211 family"))?;

        for attribute in attributes(&reply.attributes) {
            match attribute.kind {
                CTRL_ATTR_FAMILY_ID => {
                    socket.family_id = read_u16(attribute.value).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "truncated family id")
                    })?;
                }
                CTRL_ATTR_MCAST_GROUPS => {
                    socket.scan_group = multicast_group(attribute.value, "scan");
                }
                _ => {}
            }
        }
        if socket.family_id == GENL_ID_CTRL {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "nl80211 generic netlink family is unavailable",
            ));
        }

        Ok(socket)
    }

    pub fn subscribe_scan(&self) -> io::Result<()> {
        let group = self.scan_group.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "nl80211 scan multicast group is unavailable",
            )
        })?;
        let result = unsafe {
            setsockopt(
                self.fd,
                SOL_NETLINK,
                NETLINK_ADD_MEMBERSHIP,
                (&group as *const u32).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn transact(
        &mut self,
        command: u8,
        request: Vec<u8>,
        dump: bool,
    ) -> io::Result<Vec<Message>> {
        self.transact_to(self.family_id, command, request, dump)
    }

    fn transact_to(
        &mut self,
        family_id: u16,
        command: u8,
        request: Vec<u8>,
        dump: bool,
    ) -> io::Result<Vec<Message>> {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let sequence = self.sequence;
        let flags = NLM_F_REQUEST | NLM_F_ACK | if dump { NLM_F_DUMP } else { 0 };
        let packet = packet(family_id, flags, sequence, command, &request);
        let kernel = SockAddrNl {
            family: AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        let sent = unsafe {
            sendto(
                self.fd,
                packet.as_ptr().cast(),
                packet.len(),
                0,
                &kernel,
                std::mem::size_of::<SockAddrNl>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short generic netlink write",
            ));
        }

        self.receive_sequence(sequence, dump)
    }

    pub fn receive_events(&self, timeout: Duration) -> io::Result<Vec<Message>> {
        let millis = timeout.as_millis().min(c_int::MAX as u128) as c_int;
        let mut poll_fd = PollFd {
            fd: self.fd,
            events: POLLIN,
            revents: 0,
        };
        let ready = unsafe { poll(&mut poll_fd, 1, millis) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok(Vec::new());
        }
        let bytes = receive(self.fd)?;
        parse_datagram(&bytes, None).map(|parsed| parsed.messages)
    }

    fn receive_sequence(&self, sequence: u32, dump: bool) -> io::Result<Vec<Message>> {
        let mut messages = Vec::new();
        loop {
            let bytes = receive(self.fd)?;
            let parsed = parse_datagram(&bytes, Some(sequence))?;
            messages.extend(parsed.messages);
            if parsed.done || (!dump && parsed.acknowledged) {
                return Ok(messages);
            }
        }
    }
}

impl Drop for GenericSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

struct ParsedDatagram {
    messages: Vec<Message>,
    acknowledged: bool,
    done: bool,
}

fn receive(fd: c_int) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 256 * 1024];
    let length = unsafe { recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(length as usize);
    Ok(buffer)
}

fn packet(family: u16, flags: u16, sequence: u32, command: u8, attrs: &[u8]) -> Vec<u8> {
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

fn parse_datagram(bytes: &[u8], sequence: Option<u32>) -> io::Result<ParsedDatagram> {
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

pub(super) fn attributes(bytes: &[u8]) -> Vec<Attribute<'_>> {
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

pub(super) fn push_attribute(target: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = 4 + value.len();
    target.extend_from_slice(&(length as u16).to_ne_bytes());
    target.extend_from_slice(&kind.to_ne_bytes());
    target.extend_from_slice(value);
    target.resize(align4(target.len()), 0);
}

pub(super) fn push_u32(target: &mut Vec<u8>, kind: u16, value: u32) {
    push_attribute(target, kind, &value.to_ne_bytes());
}

pub(super) fn read_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?))
}

pub(super) fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

pub(super) fn read_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?))
}

fn read_i32(bytes: &[u8]) -> Option<i32> {
    Some(i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn multicast_group(bytes: &[u8], expected: &str) -> Option<u32> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_skip_padding_and_mask_flags() {
        let mut bytes = Vec::new();
        push_attribute(&mut bytes, 0x8003, &[1, 2, 3]);
        push_u32(&mut bytes, 4, 42);
        let parsed = attributes(&bytes);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, 3);
        assert_eq!(parsed[0].value, [1, 2, 3]);
        assert_eq!(read_u32(parsed[1].value), Some(42));
    }

    #[test]
    fn malformed_attribute_stops_without_panicking() {
        assert!(attributes(&[20, 0, 1, 0, 1]).is_empty());
        assert!(attributes(&[2, 0, 1, 0]).is_empty());
    }
}
