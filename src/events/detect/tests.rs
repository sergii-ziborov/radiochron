use super::*;
use std::collections::BTreeMap;

fn event(id: u32, at: i64, fields: &[(&str, &str)]) -> WlanEvent {
    let data: BTreeMap<String, String> = fields
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();

    WlanEvent {
        event_id: id,
        record_id: None,
        time_created: "2026-07-20T08:00:00.0000000Z".into(),
        epoch_seconds: at,
        meaning: super::super::meaning(id),
        data,
        named_fields: true,
    }
}

fn has(verdict: &Verdict, id: &str) -> bool {
    verdict.findings.iter().any(|f| f.id == id)
}

#[test]
fn a_roam_is_not_a_reconnect_loop() {
    // The exact pattern a healthy link produces: teardown, start, success,
    // all on one session, with a benign hint code. Repeated four times.
    let mut events = Vec::new();
    for i in 0..4 {
        let base = i * 200;
        events.push(event(
            11004,
            base,
            &[("ConnectionId", "0x11"), ("SecurityHintCode", "0")],
        ));
        events.push(event(11010, base + 1, &[("ConnectionId", "0x11")]));
        events.push(event(11005, base + 2, &[("ConnectionId", "0x11")]));
    }

    let verdict = detect(&events);
    assert!(
        !has(&verdict, "reconnect_loop"),
        "roams must not fire the loop rule"
    );
    assert!(!has(&verdict, "credential_mismatch"));
}

#[test]
fn five_failed_attempts_in_half_a_minute_is_a_loop() {
    let mut events = Vec::new();
    for i in 0..5i64 {
        let cid = format!("0x{:x}", 0xb + i);
        events.push(event(8000, i * 5, &[("ConnectionId", &cid)]));
        events.push(event(11000, i * 5 + 1, &[("ConnectionId", &cid)]));
        events.push(event(
            8002,
            i * 5 + 2,
            &[("ConnectionId", &cid), ("ReasonCode", "229396")],
        ));
    }

    let verdict = detect(&events);
    let finding = verdict
        .findings
        .iter()
        .find(|f| f.id == "reconnect_loop")
        .expect("expected a loop finding");
    assert_eq!(finding.severity, "critical");
    assert_eq!(finding.detail["attempts"], 5);
}

#[test]
fn user_requested_disconnects_never_count_as_failures() {
    let mut events = Vec::new();
    for i in 0..5i64 {
        let cid = format!("0x{i:x}");
        events.push(event(8000, i * 5, &[("ConnectionId", &cid)]));
        // ReasonCode 3: the user asked for a different network.
        events.push(event(8003, i * 5 + 2, &[("ReasonCode", "3")]));
    }

    assert!(!has(&detect(&events), "reconnect_loop"));
}

#[test]
fn successful_reassociations_do_not_trip_the_rule() {
    // Distinct sessions, but they succeed — a campus roam, not a fault.
    let mut events = Vec::new();
    for i in 0..5i64 {
        let cid = format!("0x{i:x}");
        events.push(event(8000, i * 5, &[("ConnectionId", &cid)]));
        events.push(event(8001, i * 5 + 2, &[("ConnectionId", &cid)]));
    }

    assert!(!has(&detect(&events), "reconnect_loop"));
}

#[test]
fn repeated_key_exchange_failures_name_the_access_point() {
    let events: Vec<WlanEvent> = (0..4)
        .map(|i| {
            event(
                11006,
                i * 30,
                &[("PeerMac", "0a:08:2a:aa:bb:8b"), ("ReasonCode", "0x48005")],
            )
        })
        .collect();

    let verdict = detect(&events);
    let finding = verdict
        .findings
        .iter()
        .find(|f| f.id == "access_point_key_exchange_failing")
        .expect("expected a bad-AP finding");
    assert_eq!(finding.detail["peer_mac"], "0a:08:2a:aa:bb:8b");
}

#[test]
fn failures_spread_across_hours_do_not_blame_an_access_point() {
    let events: Vec<WlanEvent> = (0..4)
        .map(|i| event(11006, i * 3600, &[("PeerMac", "0a:08:2a:aa:bb:8b")]))
        .collect();

    assert!(!has(&detect(&events), "access_point_key_exchange_failing"));
}

#[test]
fn one_psk_hint_is_a_warning_not_a_critical_claim() {
    let events = vec![event(
        11004,
        0,
        &[("SecurityHintCode", "294932"), ("SSID", "MyNet")],
    )];

    let verdict = detect(&events);
    assert_eq!(verdict.findings[0].id, "credential_mismatch");
    assert_eq!(verdict.findings[0].severity, "warning");
}

#[test]
fn repeated_psk_hints_for_one_ssid_are_critical() {
    let events = vec![
        event(
            11004,
            0,
            &[("SecurityHintCode", "294932"), ("SSID", "MyNet")],
        ),
        event(
            11004,
            30,
            &[("SecurityHintCode", "294932"), ("SSID", "MyNet")],
        ),
    ];

    let verdict = detect(&events);
    assert_eq!(verdict.findings[0].id, "credential_mismatch");
    assert_eq!(verdict.findings[0].severity, "critical");
}

#[test]
fn repeated_psk_hints_without_an_ssid_stay_a_warning() {
    let events = vec![
        event(11004, 0, &[("SecurityHintCode", "294932")]),
        event(11004, 30, &[("SecurityHintCode", "294932")]),
    ];

    let verdict = detect(&events);
    assert_eq!(verdict.findings[0].id, "credential_mismatch");
    assert_eq!(verdict.findings[0].severity, "warning");
}

#[test]
fn unnamed_fields_are_reported_rather_than_read_as_a_clean_history() {
    let mut e = event(8002, 0, &[]);
    e.named_fields = false;

    assert!(has(&detect(&[e]), "event_fields_unnamed"));
}
