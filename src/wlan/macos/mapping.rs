use alloc::format;
use alloc::string::{String, ToString};

#[cfg(feature = "scan")]
pub(super) fn channel_frequency_khz(channel: u16, band: isize) -> u32 {
    match (band, channel) {
        (1, 14) => 2_484_000,
        (1, value) => (2_407 + u32::from(value) * 5) * 1_000,
        (2, value) => (5_000 + u32::from(value) * 5) * 1_000,
        (3, value) => (5_950 + u32::from(value) * 5) * 1_000,
        (_, value) if value <= 14 => (2_407 + u32::from(value) * 5) * 1_000,
        (_, value) => (5_000 + u32::from(value) * 5) * 1_000,
    }
}

pub(super) fn phy_type(mode: isize) -> String {
    match mode {
        1 => "802.11a",
        2 => "802.11b",
        3 => "802.11g",
        4 => "ht",
        5 => "vht",
        6 => "he",
        7 => "eht",
        _ => return format!("unknown_{mode}"),
    }
    .to_string()
}
