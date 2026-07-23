use std::net::{IpAddr, ToSocketAddrs, UdpSocket};

#[cfg(any(windows, target_os = "macos"))]
use super::IpAssignment;
use super::IpConfiguration;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::platform_inspect;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::platform_inspect;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::platform_inspect;
pub(super) fn inspect(
    interface_id: &str,
    description: &str,
    route_target: Option<&str>,
) -> IpConfiguration {
    let selected_address = route_target.and_then(selected_address);
    platform_inspect(interface_id, description, selected_address)
}

fn selected_address(target: &str) -> Option<IpAddr> {
    let remote = target.to_socket_addrs().ok()?.next()?;
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.segments()[0] & 0xffc0 == 0xfe80,
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn fallback_configuration(selected: Option<IpAddr>, evidence: &str) -> IpConfiguration {
    IpConfiguration {
        assignment: selected
            .filter(|address| is_link_local(*address))
            .map(|_| IpAssignment::LinkLocal)
            .unwrap_or(IpAssignment::Unknown),
        addresses: selected.into_iter().map(|ip| ip.to_string()).collect(),
        gateway: None,
        evidence: evidence.to_string(),
    }
}
