use super::*;

#[test]
fn entries_serialise_with_a_kind_tag() {
    let entry = Entry {
        schema_version: CHRONICLE_SCHEMA_VERSION,
        device_id: Some("device-7".into()),
        boot_id: "boot-a".into(),
        sequence: 42,
        event_id: "radiochron:1:8:device-7:6:boot-a:42".into(),
        clock: ClockMetadata {
            quality: ClockQuality::Synchronized,
            source: "system_utc".into(),
            monotonic_ms: 100,
        },
        epoch_seconds: 1_784_528_615,
        time: "2026-07-20T06:23:35Z".into(),
        interface_guid: Some("guid".into()),
        kind: EntryKind::Roamed {
            from_bssid: "aa:aa:aa:aa:aa:aa".into(),
            to_bssid: "bb:bb:bb:bb:bb:bb".into(),
            rssi_dbm: -61,
        },
    };

    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"kind\":\"roamed\""), "{json}");
    assert!(json.contains("\"from_bssid\":\"aa:aa:aa:aa:aa:aa\""));
    assert!(json.contains("\"epoch_seconds\":1784528615"));
    assert!(json.contains("\"schema_version\":1"));
    assert!(json.contains("\"event_id\":\"radiochron:1:8:device-7:6:boot-a:42\""));
}

#[test]
fn event_ids_are_unambiguous_when_identity_contains_colons() {
    assert_ne!(event_id("a:b", "c", 1), event_id("a", "b:c", 1));
}
