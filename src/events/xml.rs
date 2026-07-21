//! A deliberately small extractor for the Windows Event schema.
//!
//! Not a general XML parser and not trying to be. `EvtRenderEventXml` emits a
//! narrow, machine-generated document; we need three things out of it and a
//! full parser would be a dependency and an attack surface for no gain. Every
//! function fails to `None` rather than guessing.

use std::collections::BTreeMap;

/// Text content of the first `<name>…</name>` element.
pub fn element_text(document: &str, name: &str) -> Option<String> {
    let open = format!("<{name}");
    let start = document.find(&open)?;
    // Skip any attributes on the open tag.
    let content_start = start + document[start..].find('>')? + 1;
    let close = format!("</{name}>");
    let content_end = content_start + document[content_start..].find(&close)?;

    Some(unescape(&document[content_start..content_end]))
}

/// Value of `attribute` on the first `<element …>` tag.
pub fn attribute(document: &str, element: &str, attribute: &str) -> Option<String> {
    let start = document.find(&format!("<{element}"))?;
    let tag_end = start + document[start..].find('>')?;
    let tag = &document[start..tag_end];

    // The renderer uses single quotes; accept both rather than depend on it.
    for quote in ['\'', '"'] {
        let needle = format!("{attribute}={quote}");
        if let Some(at) = tag.find(&needle) {
            let value_start = at + needle.len();
            if let Some(len) = tag[value_start..].find(quote) {
                return Some(unescape(&tag[value_start..value_start + len]));
            }
        }
    }

    None
}

/// Extract `<EventData>` children.
///
/// Returns the map plus whether the elements were *named*. `Data/@Name` is not
/// stored in the event record — it is resolved from the publisher's registered
/// manifest at render time. If that manifest is missing, Windows emits
/// positional `<Data>` elements instead, and every name-keyed lookup would
/// silently return nothing. Callers must be able to tell those apart, so
/// positional data is returned under numeric keys with the flag set false.
pub fn event_data(document: &str) -> (BTreeMap<String, String>, bool) {
    let mut fields = BTreeMap::new();
    let mut named = true;
    let mut positional = 0usize;

    let Some(section_start) = document.find("<EventData") else {
        return (fields, true);
    };
    let section = &document[section_start..];
    let section = section
        .find("</EventData>")
        .map(|end| &section[..end])
        .unwrap_or(section);

    let mut cursor = 0usize;
    while let Some(at) = section[cursor..].find("<Data") {
        let tag_start = cursor + at;
        let Some(tag_end_rel) = section[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + tag_end_rel;
        let tag = &section[tag_start..tag_end];

        // Self-closing `<Data Name='x'/>` carries an empty value.
        let (value, next) = if tag.ends_with('/') {
            (String::new(), tag_end + 1)
        } else {
            let value_start = tag_end + 1;
            match section[value_start..].find("</Data>") {
                Some(len) => (
                    unescape(&section[value_start..value_start + len]),
                    value_start + len + "</Data>".len(),
                ),
                None => break,
            }
        };

        match extract_name(tag) {
            Some(name) => {
                fields.insert(name, value);
            }
            None => {
                named = false;
                fields.insert(positional.to_string(), value);
                positional += 1;
            }
        }

        cursor = next;
    }

    (fields, named)
}

fn extract_name(tag: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let needle = format!("Name={quote}");
        if let Some(at) = tag.find(&needle) {
            let start = at + needle.len();
            if let Some(len) = tag[start..].find(quote) {
                return Some(tag[start..start + len].to_string());
            }
        }
    }

    None
}

fn unescape(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }

    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // Ampersand last, or an escaped entity would be double-decoded.
        .replace("&amp;", "&")
}

// Timestamp parsing lives in `crate::time`, shared with report rendering.
pub use crate::time::epoch_from_iso8601;

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='Microsoft-Windows-WLAN-AutoConfig'/><EventID>8002</EventID>
<TimeCreated SystemTime='2026-07-20T08:50:30.1234567Z'/></System>
<EventData><Data Name='InterfaceGuid'>{4b763cb5}</Data><Data Name='SSID'>MIXER &amp; Co</Data>
<Data Name='ReasonCode'>229396</Data><Data Name='Empty'/></EventData></Event>"#;

    #[test]
    fn extracts_id_time_and_named_data() {
        assert_eq!(element_text(SAMPLE, "EventID").as_deref(), Some("8002"));
        assert_eq!(
            attribute(SAMPLE, "TimeCreated", "SystemTime").as_deref(),
            Some("2026-07-20T08:50:30.1234567Z")
        );

        let (data, named) = event_data(SAMPLE);
        assert!(named);
        assert_eq!(data.get("SSID").unwrap(), "MIXER & Co");
        assert_eq!(data.get("ReasonCode").unwrap(), "229396");
        assert_eq!(data.get("Empty").unwrap(), "");
    }

    #[test]
    fn positional_data_is_flagged_rather_than_silently_empty() {
        // What Windows emits when the publisher manifest is unregistered.
        let doc = "<Event><EventData><Data>alpha</Data><Data>beta</Data></EventData></Event>";
        let (data, named) = event_data(doc);

        assert!(
            !named,
            "unnamed data must be reported, not treated as named"
        );
        assert_eq!(data.get("0").unwrap(), "alpha");
        assert_eq!(data.get("1").unwrap(), "beta");
    }

    #[test]
    fn an_event_without_event_data_is_not_an_error() {
        let (data, named) = event_data("<Event><System><EventID>8011</EventID></System></Event>");
        assert!(data.is_empty());
        assert!(named);
    }

    #[test]
    fn entities_decode_without_double_decoding() {
        assert_eq!(unescape("a &amp;lt; b"), "a &lt; b");
        assert_eq!(unescape("x &lt; y &amp; z"), "x < y & z");
    }

    #[test]
    fn attribute_accepts_either_quote_style() {
        assert_eq!(attribute("<T A=\"v\"/>", "T", "A").as_deref(), Some("v"));
        assert_eq!(attribute("<T A='v'/>", "T", "A").as_deref(), Some("v"));
    }
}
