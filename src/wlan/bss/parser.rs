use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{BssLoad, InformationElements, RsnDetails};

/// Walk the IE blob as 802.11 TLVs: `[id][len][valueâ€¦]`.
///
/// Pure function over bytes â€” no FFI, fully unit-testable, and the direct
/// counterpart of `SummarizeInformationElements` in the original C#.
pub fn parse_information_elements(bytes: &[u8]) -> InformationElements {
    let mut ids: Vec<u8> = Vec::new();
    let mut extension_ids: Vec<u8> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut vendor_ouis: Vec<String> = Vec::new();
    let mut has_wpa = false;
    let mut has_wps = false;
    let mut country_code = None;
    let mut channel_width_mhz = None;
    let mut bss_load = None;
    let mut rsn = None;
    let mut count = 0usize;
    let mut offset = 0usize;

    while offset + 2 <= bytes.len() {
        let id = bytes[offset];
        let len = bytes[offset + 1] as usize;
        let value_start = offset + 2;
        let next = value_start + len;

        // Truncated element: stop rather than read past the blob.
        if next > bytes.len() {
            break;
        }

        push_unique(&mut ids, id);
        push_unique_string(&mut names, ie_name(id));
        count += 1;

        let value = &bytes[value_start..next];

        match id {
            7 if value.len() >= 2 => {
                let code = &value[..2];
                if code.iter().all(u8::is_ascii_alphabetic) {
                    country_code = Some(String::from_utf8_lossy(code).to_ascii_uppercase());
                }
            }
            11 if value.len() >= 5 => {
                bss_load = Some(BssLoad {
                    station_count: u16::from_le_bytes([value[0], value[1]]),
                    channel_utilization_percent: ((u16::from(value[2]) * 100 + 127) / 255) as u8,
                    available_admission_capacity: u16::from_le_bytes([value[3], value[4]]),
                });
            }
            48 => rsn = parse_rsn(value),
            // HT Operation: both a secondary-channel offset and the STA
            // channel-width bit are required before claiming 40 MHz.
            61 if value.len() >= 2 => {
                let secondary_channel_offset = value[1] & 0x03;
                let forty_mhz_permitted = value[1] & 0x04 != 0;
                channel_width_mhz = Some(if secondary_channel_offset != 0 && forty_mhz_permitted {
                    40
                } else {
                    20
                });
            }
            // VHT Operation channel-width values: 0 preserves the HT width;
            // 1 is 80 MHz; 2 and 3 occupy 160 MHz of spectrum (contiguous or
            // 80+80 respectively).
            192 if !value.is_empty() => match value[0] {
                1 => channel_width_mhz = Some(80),
                2 | 3 => channel_width_mhz = Some(160),
                _ => {}
            },
            _ => {}
        }

        // Vendor-specific: the first three value bytes are the OUI. A 00:50:F2
        // OUI with subtype 1 is the legacy WPA (pre-RSN) element.
        if id == 221 && len >= 3 {
            let oui = format!(
                "{:02x}:{:02x}:{:02x}",
                bytes[value_start],
                bytes[value_start + 1],
                bytes[value_start + 2]
            );
            if len >= 4 && oui == "00:50:f2" && bytes[value_start + 3] == 1 {
                has_wpa = true;
            }
            if len >= 4 && oui == "00:50:f2" && bytes[value_start + 3] == 4 {
                has_wps = true;
            }
            push_unique_string(&mut vendor_ouis, oui);
        }

        if id == 255 && len >= 1 {
            let ext = bytes[value_start];
            push_unique(&mut extension_ids, ext);
            push_unique_string(&mut names, format!("Extension {ext}"));
        }

        offset = next;
    }

    ids.sort_unstable();
    extension_ids.sort_unstable();
    names.sort();
    vendor_ouis.sort();

    InformationElements {
        byte_length: bytes.len(),
        element_count: count,
        has_rsn: ids.contains(&48),
        has_wpa,
        has_bss_load: ids.contains(&11),
        has_country: ids.contains(&7),
        has_ht: ids.contains(&45) || ids.contains(&61),
        has_vht: ids.contains(&191) || ids.contains(&192),
        has_he: extension_ids.iter().any(|id| (35..=38).contains(id)),
        has_eht: extension_ids.iter().any(|id| (106..=108).contains(id)),
        has_wps,
        country_code,
        channel_width_mhz,
        bss_load,
        rsn,
        element_ids: ids,
        names,
        extension_ids,
        vendor_ouis,
    }
}

fn parse_rsn(value: &[u8]) -> Option<RsnDetails> {
    let mut offset = 0usize;
    if take_u16(value, &mut offset)? != 1 {
        return None;
    }

    let group_cipher = Some(cipher_suite(take_suite(value, &mut offset)?));
    let pairwise_count = take_u16(value, &mut offset)? as usize;
    let mut pairwise_ciphers = Vec::with_capacity(pairwise_count.min(16));
    for _ in 0..pairwise_count {
        push_unique_string(
            &mut pairwise_ciphers,
            cipher_suite(take_suite(value, &mut offset)?),
        );
    }

    let akm_count = take_u16(value, &mut offset)? as usize;
    let mut akm_suites = Vec::with_capacity(akm_count.min(16));
    for _ in 0..akm_count {
        push_unique_string(&mut akm_suites, akm_suite(take_suite(value, &mut offset)?));
    }

    let capabilities = if offset + 2 <= value.len() {
        take_u16(value, &mut offset).unwrap_or(0)
    } else {
        0
    };

    Some(RsnDetails {
        group_cipher,
        pairwise_ciphers,
        akm_suites,
        pmf_required: capabilities & (1 << 6) != 0,
        pmf_capable: capabilities & (1 << 7) != 0,
    })
}

fn take_u16(value: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = value.get(*offset..end)?;
    *offset = end;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn take_suite(value: &[u8], offset: &mut usize) -> Option<[u8; 4]> {
    let end = offset.checked_add(4)?;
    let bytes = value.get(*offset..end)?;
    *offset = end;
    Some([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn cipher_suite(suite: [u8; 4]) -> String {
    if suite[..3] != [0x00, 0x0f, 0xac] {
        return suite_name(suite);
    }
    match suite[3] {
        0 => "use-group",
        1 => "wep-40",
        2 => "tkip",
        4 => "ccmp-128",
        5 => "wep-104",
        6 => "bip-cmac-128",
        8 => "gcmp-128",
        9 => "gcmp-256",
        10 => "ccmp-256",
        11 => "bip-gmac-128",
        12 => "bip-gmac-256",
        13 => "bip-cmac-256",
        _ => return suite_name(suite),
    }
    .to_string()
}

fn akm_suite(suite: [u8; 4]) -> String {
    if suite[..3] != [0x00, 0x0f, 0xac] {
        return suite_name(suite);
    }
    match suite[3] {
        1 => "802.1x",
        2 => "psk",
        3 => "ft-802.1x",
        4 => "ft-psk",
        5 => "802.1x-sha256",
        6 => "psk-sha256",
        8 => "sae",
        9 => "ft-sae",
        11 => "802.1x-suite-b",
        12 => "802.1x-suite-b-192",
        18 => "owe",
        _ => return suite_name(suite),
    }
    .to_string()
}

fn suite_name(suite: [u8; 4]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{}",
        suite[0], suite[1], suite[2], suite[3]
    )
}

fn push_unique<T: PartialEq>(target: &mut Vec<T>, value: T) {
    if !target.contains(&value) {
        target.push(value);
    }
}

fn push_unique_string(target: &mut Vec<String>, value: String) {
    if !target
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&value))
    {
        target.push(value);
    }
}

fn ie_name(id: u8) -> String {
    match id {
        0 => "SSID",
        1 => "Supported rates",
        3 => "DS parameter set",
        5 => "TIM",
        7 => "Country",
        11 => "BSS load",
        32 => "Power constraint",
        45 => "HT capabilities",
        48 => "RSN",
        50 => "Extended supported rates",
        61 => "HT operation",
        70 => "RM enabled capabilities",
        107 => "Interworking",
        127 => "Extended capabilities",
        191 => "VHT capabilities",
        192 => "VHT operation",
        195 => "Transmit power envelope",
        201 => "Reduced neighbor report",
        221 => "Vendor specific",
        255 => "Extension",
        other => return format!("IE {other}"),
    }
    .to_string()
}
