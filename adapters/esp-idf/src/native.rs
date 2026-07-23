use alloc::string::{String, ToString};
use alloc::vec::Vec;

use embedded_svc::wifi::{AccessPointInfo, AuthMethod, Protocol};
use esp_idf_svc::sys::EspError;
use esp_idf_svc::wifi::{BlockingWifi, EspWifi, WifiEvent};

use super::{AccessPoint, Driver};
use radiochron::wlan::bss::SecurityMode;

impl<'driver> Driver for EspWifi<'driver> {
    type Error = EspError;

    fn is_connected(&mut self) -> Result<bool, Self::Error> {
        EspWifi::is_connected(self)
    }

    fn associated_access_point(&mut self) -> Result<Option<AccessPoint>, Self::Error> {
        if !EspWifi::is_connected(self)? {
            return Ok(None);
        }
        EspWifi::get_ap_info(self).map(map_access_point).map(Some)
    }

    fn scan(&mut self, output: &mut Vec<AccessPoint>) -> Result<(), Self::Error> {
        output.extend(EspWifi::scan(self)?.into_iter().map(map_access_point));
        Ok(())
    }
}

impl<'driver> Driver for BlockingWifi<EspWifi<'driver>> {
    type Error = EspError;

    fn is_connected(&mut self) -> Result<bool, Self::Error> {
        BlockingWifi::is_connected(self)
    }

    fn associated_access_point(&mut self) -> Result<Option<AccessPoint>, Self::Error> {
        if !BlockingWifi::is_connected(self)? {
            return Ok(None);
        }
        self.wifi().get_ap_info().map(map_access_point).map(Some)
    }

    fn scan(&mut self, output: &mut Vec<AccessPoint>) -> Result<(), Self::Error> {
        output.extend(BlockingWifi::scan(self)?.into_iter().map(map_access_point));
        Ok(())
    }
}

/// Extract the IEEE/ESP disconnect reason for
/// `Chronicle::observe_status_with_reason` from a system-loop callback.
pub fn disconnect_reason(event: &WifiEvent<'_>) -> Option<u16> {
    match event {
        WifiEvent::StaDisconnected(details) => Some(details.reason()),
        _ => None,
    }
}

fn map_access_point(info: AccessPointInfo) -> AccessPoint {
    AccessPoint {
        ssid: (!info.ssid.is_empty()).then(|| info.ssid.as_str().to_string()),
        bssid: info.bssid,
        channel: info.channel,
        center_frequency_khz: None,
        signal_dbm: i32::from(info.signal_strength),
        phy_type: phy_type(info.protocols),
        security: security_mode(info.auth_method),
    }
}

fn phy_type(protocols: enumset::EnumSet<Protocol>) -> String {
    if protocols.contains(Protocol::P802D11BGNLR) {
        "802.11b/g/n/lr"
    } else if protocols.contains(Protocol::P802D11BGN) {
        "802.11b/g/n"
    } else if protocols.contains(Protocol::P802D11BG) {
        "802.11b/g"
    } else if protocols.contains(Protocol::P802D11B) {
        "802.11b"
    } else if protocols.contains(Protocol::P802D11LR) {
        "802.11lr"
    } else {
        "unknown"
    }
    .to_string()
}

fn security_mode(method: Option<AuthMethod>) -> SecurityMode {
    match method {
        Some(AuthMethod::None) => SecurityMode::Open,
        Some(AuthMethod::WEP) => SecurityMode::Wep,
        Some(AuthMethod::WPA) => SecurityMode::WpaPersonal,
        Some(AuthMethod::WPA2Personal) => SecurityMode::Wpa2Personal,
        Some(AuthMethod::WPAWPA2Personal) => SecurityMode::WpaWpa2Personal,
        Some(AuthMethod::WPA2Enterprise) => SecurityMode::Wpa2Enterprise,
        Some(AuthMethod::WPA3Personal) => SecurityMode::Wpa3Personal,
        Some(AuthMethod::WPA2WPA3Personal) => SecurityMode::Wpa2Wpa3Personal,
        Some(AuthMethod::WAPIPersonal) => SecurityMode::WapiPersonal,
        None => SecurityMode::Unknown,
    }
}
