//! Calendar arithmetic, without a date crate.
//!
//! Two conversions are needed: event timestamps parse to epoch seconds for
//! windowing, and reports carry a generated-at stamp. Both are a few dozen lines
//! of Howard Hinnant's civil-days algorithm, which is exact and has no
//! dependency — whereas `chrono` would pull `windows-link`/`raw-dylib` on
//! Windows and drag the whole build-toolchain problem back in.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
pub fn now_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current UTC time as RFC 3339, e.g. `2026-07-20T08:50:30Z`.
pub fn now_iso8601() -> String {
    format_epoch(now_epoch_seconds())
}

/// Format epoch seconds as RFC 3339 UTC.
pub fn format_epoch(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let time_of_day = epoch_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

/// Parse `2026-07-20T08:50:30.1234567Z` to seconds since the Unix epoch.
///
/// Only the shape the Windows event renderer emits is accepted; anything else
/// is `None` rather than a guess.
pub fn epoch_from_iso8601(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[10] != b'T' {
        return None;
    }

    let year: i64 = value.get(0..4)?.parse().ok()?;
    let month: u32 = value.get(5..7)?.parse().ok()?;
    let day: u32 = value.get(8..10)?.parse().ok()?;
    let hour: i64 = value.get(11..13)?.parse().ok()?;
    let minute: i64 = value.get(14..16)?.parse().ok()?;
    let second: i64 = value.get(17..19)?.parse().ok()?;

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days since the Unix epoch to a civil (year, month, day).
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Inverse of [`civil_from_days`].
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as u64;
    let month = i64::from(month);
    let day_of_year = ((153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5
        + i64::from(day)
        - 1) as u64;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        // The leap-year boundary the era arithmetic exists to get right.
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }

    #[test]
    fn the_two_conversions_are_inverses() {
        for days in [0i64, 1, 11_016, 11_017, 19_723, 20_654] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(
                days_from_civil(y, m, d),
                days,
                "round trip failed at {days}"
            );
        }
    }

    #[test]
    fn parses_the_windows_event_timestamp_shape() {
        assert_eq!(epoch_from_iso8601("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            epoch_from_iso8601("2024-01-01T00:00:00.000Z"),
            Some(1_704_067_200)
        );
        assert_eq!(
            epoch_from_iso8601("2000-02-29T12:00:00Z"),
            Some(951_825_600)
        );
        assert_eq!(epoch_from_iso8601("not a timestamp"), None);
    }

    #[test]
    fn formatting_round_trips_through_parsing() {
        let stamp = format_epoch(1_784_528_615);
        assert_eq!(stamp, "2026-07-20T06:23:35Z");
        assert_eq!(epoch_from_iso8601(&stamp), Some(1_784_528_615));
    }
}
