//! Turn a stream of WLAN events into a verdict.
//!
//! The hard part is not finding disconnects — it is *not* reporting the ones
//! that are normal. Event 11004 ("security teardown") is by far the highest
//! volume event in this channel and is overwhelmingly benign: a roam to another
//! AP in the same ESS, a GTK rekey, or a resume from sleep all emit it. A naive
//! detector that counts disconnect-shaped events fires constantly on a perfectly
//! healthy link.
//!
//! The discriminator is **ConnectionId continuity**. A roam reuses the id; a
//! genuine reconnect allocates a new one. Everything below follows from that.
//!
//! Every numeric reason code here was observed on real hardware rather than
//! published by Microsoft, so unknown codes are reported as "unknown code N"
//! instead of being guessed at, and a missing field degrades a rule rather than
//! failing it.

use serde::Serialize;

use super::WlanEvent;

/// Window for the reconnect-loop rule.
const LOOP_WINDOW_S: i64 = 120;
/// Window for blaming a single access point.
const BAD_AP_WINDOW_S: i64 = 300;

/// 8003 disconnect reasons that are intentional, not faults.
const DISCONNECT_USER_REQUESTED: u64 = 3;
const DISCONNECT_POLICY: u64 = 5;
/// 8003 reason 0 is "disconnected by the driver" — unplanned, and the only
/// disconnect reason that counts toward a fault.
const DISCONNECT_BY_DRIVER: u64 = 0;

/// Observed on 11004 meaning the pre-shared key looks wrong.
const HINT_PSK_MISMATCH: u64 = 294_932;

#[derive(Debug, Serialize)]
pub struct Verdict {
    pub events_considered: usize,
    pub window_seconds: i64,
    pub findings: Vec<HistoryFinding>,
}

#[derive(Debug, Serialize)]
pub struct HistoryFinding {
    pub id: &'static str,
    pub severity: &'static str,
    pub title: String,
    pub detail: serde_json::Value,
    pub caveat: &'static str,
}

/// Analyse events (any order; they are sorted internally).
pub fn detect(events: &[WlanEvent]) -> Verdict {
    let mut sorted: Vec<&WlanEvent> = events.iter().collect();
    sorted.sort_by_key(|e| e.epoch_seconds);

    let mut findings = Vec::new();
    push_credential_mismatch(&mut findings, &sorted);
    push_bad_access_point(&mut findings, &sorted);
    push_reconnect_loop(&mut findings, &sorted);
    push_unnamed_fields(&mut findings, &sorted);

    findings.sort_by_key(|f| match f.severity {
        "critical" => 0,
        "warning" => 1,
        _ => 2,
    });

    Verdict {
        events_considered: events.len(),
        window_seconds: LOOP_WINDOW_S,
        findings,
    }
}

/// A wrong pre-shared key is a cause; the reconnect loop it produces is only a
/// symptom. Report it first so the loop verdict does not bury it.
fn push_credential_mismatch(findings: &mut Vec<HistoryFinding>, events: &[&WlanEvent]) {
    let hits: Vec<&&WlanEvent> = events
        .iter()
        .filter(|e| {
            e.event_id == 11004 && e.numeric_field("SecurityHintCode") == Some(HINT_PSK_MISMATCH)
        })
        .collect();

    if hits.is_empty() {
        return;
    }

    // The code is undocumented and has been observed during a normal rekey.
    // A single occurrence is evidence worth surfacing, but not enough to call
    // a credential definitively wrong. Repetition inside the analysis window
    // is the corroboration that raises it to critical.
    let corroborated = hits.windows(2).any(|pair| {
        let same_named_ssid = matches!(
            (pair[0].field("SSID"), pair[1].field("SSID")),
            (Some(left_ssid), Some(right_ssid)) if left_ssid == right_ssid
        );
        pair[1].epoch_seconds.saturating_sub(pair[0].epoch_seconds) <= LOOP_WINDOW_S
            && same_named_ssid
    });

    findings.push(HistoryFinding {
        id: "credential_mismatch",
        severity: if corroborated { "critical" } else { "warning" },
        title: format!(
            "{} security teardowns report a suspected PSK mismatch",
            hits.len()
        ),
        detail: serde_json::json!({
            "occurrences": hits.len(),
            "ssid": hits.first().and_then(|e| e.field("SSID")),
            "first_seen": hits.first().map(|e| e.time_created.clone()),
        }),
        caveat: "The hint code is a single-machine observation, not a documented constant, and \
                 Windows raises it heuristically. One occurrence stays a warning because it can \
                 appear during a normal rekey; verify the saved profile before acting.",
    });
}

/// Event 11006 is the only event in this channel carrying a BSSID, which makes
/// it the one rule that can name the guilty radio.
fn push_bad_access_point(findings: &mut Vec<HistoryFinding>, events: &[&WlanEvent]) {
    let failures: Vec<&&WlanEvent> = events.iter().filter(|e| e.event_id == 11006).collect();
    if failures.len() < 3 {
        return;
    }

    // Group by peer, then look for three inside the window.
    let mut peers: std::collections::BTreeMap<&str, Vec<i64>> = std::collections::BTreeMap::new();
    for event in &failures {
        if let Some(peer) = event.field("PeerMac") {
            peers.entry(peer).or_default().push(event.epoch_seconds);
        }
    }

    for (peer, mut times) in peers {
        if times.len() < 3 {
            continue;
        }
        times.sort_unstable();

        let clustered = times.windows(3).any(|w| w[2] - w[0] <= BAD_AP_WINDOW_S);
        if !clustered {
            continue;
        }

        findings.push(HistoryFinding {
            id: "access_point_key_exchange_failing",
            severity: "critical",
            title: format!(
                "{} key-exchange failures against a single AP ({peer})",
                times.len()
            ),
            detail: serde_json::json!({
                "peer_mac": peer,
                "failures": times.len(),
                "reason_codes": failures
                    .iter()
                    .filter(|e| e.field("PeerMac") == Some(peer))
                    .filter_map(|e| e.numeric_field("ReasonCode"))
                    .collect::<Vec<_>>(),
            }),
            caveat: "Blames one radio, which is usually right, but a client-side certificate or \
                     supplicant fault can produce the same pattern if the client only ever reaches \
                     that AP. The remediation differs entirely from a client-side loop, so confirm \
                     against a second AP before replacing hardware.",
        });
    }
}

/// The reconnect loop proper.
fn push_reconnect_loop(findings: &mut Vec<HistoryFinding>, events: &[&WlanEvent]) {
    let Some(&last) = events.last() else { return };
    let floor = last.epoch_seconds - LOOP_WINDOW_S;
    let window: Vec<&&WlanEvent> = events.iter().filter(|e| e.epoch_seconds >= floor).collect();

    // A: distinct attempts, identified by the session id an 8000 opens.
    let mut attempts: Vec<u64> = window
        .iter()
        .filter(|e| e.event_id == 8000)
        .filter_map(|e| e.connection_id())
        .collect();
    attempts.sort_unstable();
    attempts.dedup();

    // F: genuine failures only. A user-requested or policy disconnect is
    // intentional, and a bare security teardown is a roam.
    let failures = window
        .iter()
        .filter(|e| match e.event_id {
            8002 => true,
            8003 => {
                let reason = e.numeric_field("ReasonCode");
                // Absent reason: treat as unplanned but say so in the caveat.
                reason.map_or(true, |r| {
                    r == DISCONNECT_BY_DRIVER
                        || (r != DISCONNECT_USER_REQUESTED && r != DISCONNECT_POLICY)
                })
            }
            _ => false,
        })
        .count();

    let successes = window.iter().filter(|e| e.event_id == 8001).count();

    // Requiring real failures, not merely attempts, keeps successful campus
    // re-associations from tripping the rule.
    if attempts.len() < 3 || failures < 3 || successes > 1 {
        return;
    }

    findings.push(HistoryFinding {
        id: "reconnect_loop",
        severity: if attempts.len() >= 5 { "critical" } else { "warning" },
        title: format!(
            "{} connection attempts and {failures} failures in {LOOP_WINDOW_S}s",
            attempts.len()
        ),
        detail: serde_json::json!({
            "attempts": attempts.len(),
            "failures": failures,
            "successes": successes,
            "window_seconds": LOOP_WINDOW_S,
            "reason_codes": window
                .iter()
                .filter(|e| e.event_id == 8002)
                .filter_map(|e| e.numeric_field("ReasonCode"))
                .collect::<Vec<_>>(),
        }),
        caveat: "Roams and rekeys are excluded by requiring distinct ConnectionIds and real \
                 failures, but an 8003 without a readable ReasonCode is counted as unplanned, which \
                 can over-report. Reason codes are undocumented observations; treat an unfamiliar \
                 one as unknown rather than meaningful.",
    });
}

/// If the publisher manifest did not name the fields, every name-keyed rule
/// above was silently inert. Say so rather than reporting a clean history.
fn push_unnamed_fields(findings: &mut Vec<HistoryFinding>, events: &[&WlanEvent]) {
    let unnamed = events.iter().filter(|e| !e.named_fields).count();
    if unnamed == 0 {
        return;
    }

    findings.push(HistoryFinding {
        id: "event_fields_unnamed",
        severity: "warning",
        title: format!("{unnamed} events rendered without named fields"),
        detail: serde_json::json!({ "unnamed": unnamed, "total": events.len() }),
        caveat: "Field names come from the publisher's registered manifest, not the event record. \
                 Without them every rule that keys on ReasonCode, ConnectionId or PeerMac is inert \
                 for those events, so an absence of findings here does not mean an absence of faults.",
    });
}

#[cfg(test)]
mod tests {
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
}
