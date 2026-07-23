use std::net::IpAddr;

use super::is_link_local;
use crate::connectivity::{IpAssignment, IpConfiguration};
#[cfg(target_os = "linux")]
pub(super) fn platform_inspect(
    interface_id: &str,
    interface_name: &str,
    selected: Option<IpAddr>,
) -> IpConfiguration {
    use std::fs;
    use std::path::{Path, PathBuf};

    let index = interface_id
        .strip_prefix("ifindex:")
        .unwrap_or(interface_id);
    let mut addresses = selected
        .into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();
    let lease_path = PathBuf::from(format!("/run/systemd/netif/leases/{index}"));
    if let Ok(lease) = fs::read_to_string(&lease_path) {
        let lease_address = value(&lease, "ADDRESS");
        if let Some(address) = lease_address.as_deref() {
            let address = address.split('/').next().unwrap_or(address).to_string();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        return IpConfiguration {
            assignment: IpAssignment::Dhcp,
            addresses,
            gateway: value(&lease, "ROUTER").or_else(|| linux_gateway(interface_name)),
            evidence: format!("active systemd-networkd lease {}", lease_path.display()),
        };
    }

    if network_manager_lease_matches(interface_name, selected) {
        return IpConfiguration {
            assignment: IpAssignment::Dhcp,
            addresses,
            gateway: linux_gateway(interface_name),
            evidence: "active address matches a NetworkManager/dhclient lease".to_string(),
        };
    }

    let link_path = PathBuf::from(format!("/run/systemd/netif/links/{index}"));
    if let Ok(link) = fs::read_to_string(&link_path) {
        if let Some(network_file) = value(&link, "NETWORK_FILE") {
            if let Ok(configuration) = fs::read_to_string(&network_file) {
                let dhcp = ini_value(&configuration, "DHCP").unwrap_or_default();
                let has_static = configuration
                    .lines()
                    .map(str::trim)
                    .any(|line| line.starts_with("Address="));
                if matches!(dhcp.to_ascii_lowercase().as_str(), "no" | "false" | "0") && has_static
                {
                    return IpConfiguration {
                        assignment: IpAssignment::Static,
                        addresses,
                        gateway: linux_gateway(interface_name),
                        evidence: format!(
                            "active systemd-networkd profile {network_file} explicitly disables DHCP and defines Address"
                        ),
                    };
                }
            }
        }
    }

    let assignment = if selected.is_some_and(is_link_local) {
        IpAssignment::LinkLocal
    } else {
        IpAssignment::Unknown
    };
    let evidence = match assignment {
        IpAssignment::LinkLocal => "route selected a link-local address".to_string(),
        _ => "no matching DHCP lease or explicit active static profile was found".to_string(),
    };
    return IpConfiguration {
        assignment,
        addresses,
        gateway: linux_gateway(interface_name),
        evidence,
    };

    fn value(contents: &str, name: &str) -> Option<String> {
        contents.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == name).then(|| value.trim().trim_matches('"').to_string())
        })
    }

    fn ini_value(contents: &str, name: &str) -> Option<String> {
        value(contents, name)
    }

    fn network_manager_lease_matches(interface: &str, selected: Option<IpAddr>) -> bool {
        let Some(selected) = selected else {
            return false;
        };
        let needle = selected.to_string();
        [
            Path::new("/var/lib/NetworkManager"),
            Path::new("/var/lib/dhcp"),
            Path::new("/run/NetworkManager"),
        ]
        .into_iter()
        .filter_map(|directory| fs::read_dir(directory).ok())
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .any(|lease| {
            lease.contains(&needle)
                && (lease.contains(&format!("interface \"{interface}\""))
                    || lease.contains("fixed-address")
                    || lease.contains("ADDRESS="))
        })
    }

    fn linux_gateway(interface: &str) -> Option<String> {
        let routes = fs::read_to_string("/proc/net/route").ok()?;
        routes.lines().skip(1).find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 || fields[0] != interface || fields[1] != "00000000" {
                return None;
            }
            let raw = u32::from_str_radix(fields[2], 16).ok()?;
            Some(std::net::Ipv4Addr::from(raw.to_le_bytes()).to_string())
        })
    }
}
