//! The WLAN AutoConfig event log — the history a snapshot cannot provide.
//!
//! A current-state reading cannot answer "why did it drop ten minutes ago".
//! This reads `Microsoft-Windows-WLAN-AutoConfig/Operational` through hand-
//! written runtime-loaded FFI to `wevtapi.dll`.
//!
//! **The locale problem, and why this design avoids it.** `Get-WinEvent` hands
//! back a fully-rendered, *localized* `Message` string, and the predecessor
//! TypeScript app parsed that text — so it silently produced nothing on a German
//! or Japanese Windows. `EvtRenderEventXml` instead yields the raw event XML
//! with structured `EventData`, which is locale-invariant, and requires neither
//! `EvtFormatMessage` nor a publisher-metadata handle. Every rule below keys on
//! numeric codes, never on prose.
//!
//! **Why not `EvtRenderEventValues`.** That path forces a hand-declared
//! `EVT_VARIANT` — a tagged union whose size and padding differ between x64 and
//! arm64, where a mistake is silent memory corruption rather than a compile
//! error. The XML path costs a small extractor and removes every union from this
//! module.
//!
//! **Trust boundaries.** Event IDs here are confirmed against Microsoft
//! documentation and the NSA event-forwarding baseline. `EventData` *field
//! names* and *numeric reason codes* are not published by Microsoft; they were
//! observed on real hardware and are therefore treated as optional throughout —
//! a missing field degrades a finding, never panics.

mod sys;

use std::collections::BTreeMap;

use serde::Serialize;

pub mod detect;
mod xml;

pub use detect::{detect, Verdict};

/// The channel. Confirmed; note it is an Operational channel, not Security.
const CHANNEL: &str = "Microsoft-Windows-WLAN-AutoConfig/Operational";

/// One decoded event.
#[derive(Debug, Clone, Serialize)]
pub struct WlanEvent {
    pub event_id: u32,
    /// Monotonic record identity assigned by the Windows event log. Unlike a
    /// timestamp it distinguishes multiple records written in the same second.
    pub record_id: Option<u64>,
    /// ISO 8601, straight from the event record's `TimeCreated/@SystemTime`.
    pub time_created: String,
    /// Seconds since the Unix epoch, derived from `time_created` for windowing.
    pub epoch_seconds: i64,
    pub meaning: &'static str,
    /// Locale-invariant `EventData` fields. Empty when the publisher manifest
    /// did not name them — see `named_fields`.
    pub data: BTreeMap<String, String>,
    /// False when the record rendered positional `<Data>` elements rather than
    /// named ones, which happens if the publisher manifest is unregistered. Every
    /// name-keyed rule must be skipped for such an event rather than silently
    /// reading nothing.
    pub named_fields: bool,
}

impl WlanEvent {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.data.get(name).map(String::as_str)
    }

    /// Parse a field written as `0x...` or decimal.
    pub fn numeric_field(&self, name: &str) -> Option<u64> {
        let raw = self.field(name)?.trim();
        let parsed = raw
            .strip_prefix("0x")
            .or_else(|| raw.strip_prefix("0X"))
            .map(|hex| u64::from_str_radix(hex, 16))
            .unwrap_or_else(|| raw.parse::<u64>());
        parsed.ok()
    }

    /// The session identifier that ties one connection attempt together.
    ///
    /// Event 11001 was observed encoding it in the high dword. That is a
    /// single-machine observation, so rather than shifting unconditionally we
    /// shift only when the value cannot be a low-dword id — correct under both
    /// hypotheses, at the cost of one comparison.
    pub fn connection_id(&self) -> Option<u64> {
        let raw = self.numeric_field("ConnectionId")?;
        if raw > u64::from(u32::MAX) {
            Some(raw >> 32)
        } else {
            Some(raw)
        }
    }

    /// The 8xxx family names it `InterfaceGuid`, the 11xxx family `DeviceGuid`.
    pub fn interface_guid(&self) -> Option<&str> {
        self.field("InterfaceGuid")
            .or_else(|| self.field("DeviceGuid"))
    }
}

/// What each confirmed event ID means. Unknown IDs are surfaced, not dropped —
/// an unrecognised event is still evidence something happened.
pub fn meaning(event_id: u32) -> &'static str {
    match event_id {
        8000 => "connection attempt started",
        8001 => "connection succeeded",
        8002 => "connection failed",
        8003 => "disconnected",
        8011 => "network visible, auto-connect pending",
        11000 => "association started",
        11001 => "association succeeded",
        11002 => "association aborted",
        11004 => "security teardown",
        11005 => "security succeeded",
        11006 => "security failed",
        11010 => "security started",
        12011 => "802.1X authentication started",
        12012 => "802.1X authentication succeeded",
        12013 => "802.1X authentication failed",
        _ => "unrecognised event",
    }
}

/// Read the most recent events, newest first.
///
/// `within_seconds` bounds how far back to look; `max` bounds how many to
/// return. Both exist because a busy machine writes thousands of these.
pub fn recent(max: usize, within_seconds: Option<u64>) -> anyhow::Result<Vec<WlanEvent>> {
    let raw = sys::query_xml(CHANNEL, max, within_seconds)?;
    let now = crate::time::now_epoch_seconds();

    let mut events: Vec<WlanEvent> = raw
        .iter()
        .enumerate()
        .map(|(index, xml)| {
            decode(xml)
                .map_err(|error| anyhow::anyhow!("failed to decode WLAN event {index}: {error}"))
        })
        .collect::<anyhow::Result<_>>()?;

    if let Some(window) = within_seconds {
        let window = i64::try_from(window).unwrap_or(i64::MAX);
        let floor = now.saturating_sub(window);
        events.retain(|event| event.epoch_seconds >= floor);
    }

    Ok(events)
}

fn decode(document: &str) -> anyhow::Result<WlanEvent> {
    let event_id: u32 = xml::element_text(document, "EventID")
        .ok_or_else(|| anyhow::anyhow!("missing EventID"))?
        .trim()
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid EventID: {error}"))?;
    let record_id = xml::element_text(document, "EventRecordID")
        .map(|value| value.trim().parse::<u64>())
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid EventRecordID: {error}"))?;
    let time_created = xml::attribute(document, "TimeCreated", "SystemTime")
        .ok_or_else(|| anyhow::anyhow!("missing TimeCreated/SystemTime"))?;
    let epoch_seconds = xml::epoch_from_iso8601(&time_created)
        .ok_or_else(|| anyhow::anyhow!("invalid SystemTime: {time_created}"))?;
    let (data, named_fields) = xml::event_data(document);

    Ok(WlanEvent {
        event_id,
        record_id,
        epoch_seconds,
        time_created,
        meaning: meaning(event_id),
        data,
        named_fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: u32, fields: &[(&str, &str)]) -> WlanEvent {
        WlanEvent {
            event_id: id,
            record_id: None,
            time_created: "2026-07-20T08:00:00.0000000Z".into(),
            epoch_seconds: 0,
            meaning: meaning(id),
            data: fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            named_fields: true,
        }
    }

    #[test]
    fn numeric_fields_accept_hex_and_decimal() {
        let e = event(8002, &[("ReasonCode", "229396"), ("Other", "0x48005")]);
        assert_eq!(e.numeric_field("ReasonCode"), Some(229_396));
        assert_eq!(e.numeric_field("Other"), Some(0x48005));
        assert_eq!(e.numeric_field("Absent"), None);
    }

    #[test]
    fn connection_id_shifts_only_when_the_value_cannot_be_a_low_dword() {
        // The observed 11001 encoding.
        let packed = event(11001, &[("ConnectionId", "0x1300000001")]);
        assert_eq!(packed.connection_id(), Some(0x13));

        // A plain id must survive untouched, whatever the event.
        let plain = event(11001, &[("ConnectionId", "0x13")]);
        assert_eq!(plain.connection_id(), Some(0x13));
    }

    #[test]
    fn interface_guid_accepts_either_family_spelling() {
        assert_eq!(
            event(8000, &[("InterfaceGuid", "{abc}")]).interface_guid(),
            Some("{abc}")
        );
        assert_eq!(
            event(11004, &[("DeviceGuid", "{abc}")]).interface_guid(),
            Some("{abc}")
        );
    }

    #[test]
    fn unrecognised_ids_are_surfaced_not_dropped() {
        assert_eq!(meaning(99999), "unrecognised event");
    }

    #[test]
    fn decode_preserves_event_record_id_for_lossless_tailing() {
        let document = r#"<Event><System><EventID>8001</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-07-20T08:00:00.0000000Z"/></System><EventData/></Event>"#;
        let decoded = decode(document).unwrap();
        assert_eq!(decoded.record_id, Some(42));
    }
}
