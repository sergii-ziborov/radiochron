use std::ffi::c_void;
use std::io;
use std::os::raw::c_int;
#[cfg(feature = "scan")]
use std::os::raw::c_short;
#[cfg(feature = "scan")]
use std::time::Duration;

use super::wire::{
    attributes, multicast_group, packet, parse_datagram, push_attribute, read_u16, Message,
    CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_MCAST_GROUPS, CTRL_CMD_GETFAMILY,
    GENL_ID_CTRL, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
const AF_NETLINK: c_int = 16;
const SOCK_RAW: c_int = 3;
const NETLINK_GENERIC: c_int = 16;
#[cfg(feature = "scan")]
const SOL_NETLINK: c_int = 270;
#[cfg(feature = "scan")]
const NETLINK_ADD_MEMBERSHIP: c_int = 1;
#[cfg(feature = "scan")]
const POLLIN: c_short = 0x0001;

#[repr(C)]
struct SockAddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

#[repr(C)]
#[cfg(feature = "scan")]
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
    #[cfg(feature = "scan")]
    fn setsockopt(
        fd: c_int,
        level: c_int,
        option: c_int,
        value: *const c_void,
        length: u32,
    ) -> c_int;
    #[cfg(feature = "scan")]
    fn poll(fds: *mut PollFd, count: usize, timeout_ms: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

pub(crate) struct GenericSocket {
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

    #[cfg(feature = "scan")]
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

    #[cfg(feature = "scan")]
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

fn receive(fd: c_int) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 256 * 1024];
    let length = unsafe { recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(length as usize);
    Ok(buffer)
}
