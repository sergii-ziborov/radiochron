//! The Model Context Protocol surface: newline-delimited JSON-RPC 2.0 on stdio.
//!
//! Implemented directly rather than through an SDK. The transport is one JSON
//! object per line and the server only has to answer `initialize`,
//! `tools/list`, `tools/call` and `ping`, so a dependency that pulls an async
//! runtime, a schema generator and a mandatory `chrono` is poor value — and
//! `chrono`'s `clock` feature would drag in `windows-link`/`raw-dylib`,
//! reintroducing the very build-toolchain requirement this project avoids.
//!
//! Every tool is read-only. The sensitive collectors the parent project grew —
//! plaintext saved Wi-Fi keys, adapter MAC changes, adapter restarts, active LAN
//! sweeps, shelling out to an external AI CLI — are deliberately not exposed. An
//! autonomous model must not be able to leak a credential or drop the operator
//! off the network by calling a tool.

use std::io::{BufRead, Write};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use beacontrail::wlan;
use beacontrail::wlan::bss::BssSummary;

/// MCP revision this server implements.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Dwell time after asking the driver to scan before reading the BSS list.
/// Windows reports scan completion asynchronously.
const SCAN_SETTLE: Duration = Duration::from_secs(4);

// JSON-RPC 2.0 error codes.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INTERNAL_ERROR: i64 = -32603;
/// MCP reserves this specifically for an unknown resource URI. Note the
/// asymmetry with tools: a tool failure is reported inside the result as
/// `isError`, but a resource failure is a real JSON-RPC error.
const RESOURCE_NOT_FOUND: i64 = -32002;

const URI_REPORT_MD: &str = "beacontrail://report/latest";
const URI_REPORT_JSON: &str = "beacontrail://report/latest.json";
const URI_STATUS: &str = "beacontrail://status";
const URI_NETWORKS: &str = "beacontrail://networks";

/// Serve MCP on stdin/stdout until the client closes the stream.
///
/// stdout carries JSON-RPC frames and nothing else; diagnostics go to stderr.
pub fn serve_stdio() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        if let Some(response) = handle_line(&line) {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }

    Ok(())
}

/// Handle one incoming frame. Returns `None` for notifications, which by
/// JSON-RPC rule must not be answered.
fn handle_line(line: &str) -> Option<String> {
    // Windows tooling emits a UTF-8 BOM with depressing regularity; a stray one
    // at the head of the stream must not kill the session.
    let line = line.trim_start_matches('\u{feff}');

    let message: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(error) => {
            return Some(error_response(Value::Null, PARSE_ERROR, &error.to_string()));
        }
    };

    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str);

    let Some(method) = method else {
        let id = id.unwrap_or(Value::Null);
        return Some(error_response(id, INVALID_REQUEST, "missing method"));
    };

    // No id means a notification: act on it, answer nothing.
    let id = id?;

    let params = message.get("params").cloned().unwrap_or(Value::Null);

    match dispatch(method, &params) {
        Ok(result) => Some(success_response(id, result)),
        Err(RpcError { code, message }) => Some(error_response(id, code, &message)),
    }
}

struct RpcError {
    code: i64,
    message: String,
}

fn dispatch(method: &str, params: &Value) -> Result<Value, RpcError> {
    match method {
        "initialize" => Ok(initialize_result()),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => call_tool(params),
        "resources/list" => Ok(json!({ "resources": resource_definitions() })),
        // Several clients probe this unconditionally after initialize; an empty
        // array costs three lines and avoids a red -32601 in their logs.
        "resources/templates/list" => Ok(json!({ "resourceTemplates": [] })),
        "resources/read" => read_resource(params),
        other => Err(RpcError {
            code: METHOD_NOT_FOUND,
            message: format!("unknown method: {other}"),
        }),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        // Neither subscribe nor listChanged: the resource set is a fixed table,
        // and "changed" is ill-defined when RSSI jitters every beacon interval.
        "capabilities": {
            "tools": { "listChanged": false },
            "resources": { "subscribe": false, "listChanged": false }
        },
        "serverInfo": {
            "name": "beacontrail",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "BeaconTrail reads local Windows Wi-Fi state directly from the native \
                         WLAN API. Use wifi_status for the current connection, wifi_networks for \
                         nearby access points with real dBm and 802.11 capability flags, and \
                         wifi_scan to force a refresh. All tools are read-only and Windows-only; \
                         nothing is transmitted off the machine. SSIDs, BSSIDs and MAC addresses \
                         are sensitive — do not repeat them into untrusted contexts."
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "wifi_status",
            "description": "Current Wi-Fi state: every WLAN interface, its connection state, and \
                            for the associated one the SSID, BSSID, PHY type (ht/vht/he/eht), \
                            signal quality, estimated RSSI in dBm, and rx/tx rates. Read-only.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "wifi_networks",
            "description": "Nearby access points from the native WLAN BSS list: SSID, BSSID, real \
                            RSSI in dBm, band and channel, PHY type, and 802.11 security and \
                            capability flags parsed from the beacon information elements \
                            (RSN/WPA/HT/VHT/HE/EHT). Returns {count, refreshed, detail, networks}. \
                            If the driver's cache comes back empty it is retried once behind a \
                            real scan, and `refreshed` reports whether that happened. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "refresh_scan": {
                        "type": "boolean",
                        "description": "Force a fresh driver scan and wait ~4s before reading. \
                                        Cached results are returned immediately without it, but \
                                        the cache can be sparse or stale — prefer this when the \
                                        completeness of the list matters."
                    },
                    "detail": {
                        "type": "string",
                        "enum": ["summary", "full"],
                        "description": "summary (default) returns ssid, bssid, band, channel, \
                                        rssi_dbm, phy_type, security and caps. full adds raw IE \
                                        ids and names, rates, timestamps and capability bits, and \
                                        is several times larger — request it only when the extra \
                                        fields are actually needed."
                    }
                }
            }
        },
        {
            "name": "wifi_analyze",
            "description": "Diagnose the radio environment and return findings rather than records: \
                            co-channel contention, whether the associated AP sits on a crowded channel, \
                            weak signal, a stronger band or nearer AP carrying the same SSID, insecure \
                            or legacy security, hidden SSIDs, and scan-quality problems. Prefer this \
                            over wifi_networks when the question is 'what is wrong' rather than 'what \
                            is there'. Every finding carries a `caveat` stating why it may be wrong — \
                            read it before repeating the conclusion. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "refresh_scan": {
                        "type": "boolean",
                        "description": "Force a fresh driver scan and wait ~4s first. Recommended, \
                                        since findings computed over a stale cache are unreliable."
                    }
                }
            }
        },
        {
            "name": "wifi_history",
            "description": "Read the Windows WLAN AutoConfig event log and return a verdict: \
                            reconnect loops, an access point repeatedly failing key exchange, and \
                            suspected credential mismatch. This is the tool that answers 'why did it \
                            drop earlier' — a current-state reading cannot. Roams and rekeys are \
                            deliberately excluded: they are the highest-volume events in this log and \
                            are almost always benign. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "within_seconds": {
                        "type": "integer",
                        "description": "How far back to look. Default 3600."
                    },
                    "max_events": {
                        "type": "integer",
                        "description": "Cap on events read. Default 200, hard limit 2000."
                    },
                    "include_events": {
                        "type": "boolean",
                        "description": "Also return the raw decoded events. Off by default — the \
                                        verdict is the useful part and the raw list is large."
                    }
                }
            }
        },
        {
            "name": "wifi_sample",
            "description": "Sample the current association over a bounded window and return both the \
                            series and the aggregates a single snapshot cannot show: RSSI min/max/mean \
                            and peak-to-trough swing, rx-rate range, distinct BSSIDs seen, roam count, \
                            and how many samples were disconnected. Use this when the complaint is \
                            instability (drops, stalls, slowness) rather than a current-state question. \
                            BLOCKS for the requested duration. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "duration_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 120,
                        "description": "How long to sample. Default 20. Capped at 120 because the call \
                                        blocks the JSON-RPC channel for its whole duration."
                    },
                    "interval_ms": {
                        "type": "integer",
                        "minimum": 250,
                        "description": "Delay between readings. Default 1000, floor 250."
                    }
                }
            }
        },
        {
            "name": "wifi_scan",
            "description": "Ask every WLAN interface to perform a fresh scan. Returns how many \
                            interfaces accepted the request. Results arrive asynchronously — read \
                            them with wifi_networks a few seconds later. Emits no network traffic \
                            beyond a standard Wi-Fi scan.",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ])
}

fn resource_definitions() -> Value {
    json!([
        {
            "uri": URI_REPORT_MD,
            "name": "wifi_diagnostic_report",
            "title": "Wi-Fi Diagnostic Report",
            "description": "Adapter state, current association, per-band census, findings, and the \
                            strongest visible BSS. Rendered from cached scan results on every read.",
            "mimeType": "text/markdown",
            "annotations": { "audience": ["user", "assistant"], "priority": 0.9 }
        },
        {
            "uri": URI_REPORT_JSON,
            "name": "wifi_diagnostic_report_json",
            "title": "Wi-Fi Diagnostic Report (JSON)",
            "description": "Machine-readable form of the same snapshot, including the full findings list.",
            "mimeType": "application/json",
            "annotations": { "audience": ["assistant"], "priority": 0.5 }
        },
        {
            "uri": URI_STATUS,
            "name": "wifi_status",
            "title": "Current Wi-Fi Connection",
            "description": "Per-interface association state: SSID, BSSID, PHY type, signal quality, \
                            RSSI estimate and rx/tx rates.",
            "mimeType": "application/json"
        },
        {
            "uri": URI_NETWORKS,
            "name": "wifi_networks",
            "title": "Visible Networks",
            "description": "Compact list of nearby BSS from the cached scan.",
            "mimeType": "application/json"
        }
    ])
}

/// Serve a resource from the cached scan.
///
/// Never triggers a scan: a client may read speculatively or on every turn, and
/// a hidden four-second stall on a passive read is bad behaviour. `wifi_scan`
/// stays the only thing that forces a refresh.
fn read_resource(params: &Value) -> Result<Value, RpcError> {
    let uri = params.get("uri").and_then(Value::as_str).ok_or(RpcError {
        code: INVALID_REQUEST,
        message: "resources/read requires a uri".to_string(),
    })?;

    // Exact match against a fixed table. Never substring-match or path-join, or
    // a server that touches no filesystem acquires a traversal bug anyway.
    let (mime, body) = match uri {
        URI_REPORT_MD => ("text/markdown", render(Format::Markdown)),
        URI_REPORT_JSON => ("application/json", render(Format::Json)),
        URI_STATUS => ("application/json", render(Format::Status)),
        URI_NETWORKS => ("application/json", render(Format::Networks)),
        other => {
            return Err(RpcError {
                code: RESOURCE_NOT_FOUND,
                message: format!("resource not found: {other}"),
            })
        }
    };

    let text = body.map_err(|error| RpcError {
        code: INTERNAL_ERROR,
        message: error.to_string(),
    })?;

    Ok(json!({
        "contents": [{ "uri": uri, "mimeType": mime, "text": text }]
    }))
}

enum Format {
    Markdown,
    Json,
    Status,
    Networks,
}

fn render(format: Format) -> anyhow::Result<String> {
    let status = wlan::wifi_status().unwrap_or_default();

    match format {
        Format::Status => encode(&status),
        Format::Networks => {
            let entries = wlan::bss::bss_list()?;
            encode(&entries.iter().map(BssSummary::from).collect::<Vec<_>>())
        }
        Format::Markdown | Format::Json => {
            let entries = wlan::bss::bss_list()?;
            let connection = status.iter().find_map(|entry| entry.connection.as_ref());
            let analysis = wlan::analyze::analyze(&entries, connection);

            match format {
                Format::Markdown => Ok(crate::report::markdown(&status, &entries, &analysis)),
                _ => encode(&crate::report::json(&status, &entries, &analysis)),
            }
        }
    }
}

fn call_tool(params: &Value) -> Result<Value, RpcError> {
    let name = params.get("name").and_then(Value::as_str).ok_or(RpcError {
        code: INVALID_REQUEST,
        message: "tools/call requires a name".to_string(),
    })?;
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    // A failing collector is reported as a tool error, not a protocol error, so
    // the model can read the reason and adapt instead of losing the session.
    let outcome = match name {
        "wifi_status" => wlan::wifi_status().and_then(|v| encode(&v)),
        "wifi_scan" => wlan::bss::request_scan()
            .and_then(|count| encode(&json!({ "interfaces_scanning": count }))),
        "wifi_networks" => collect_networks(&arguments).and_then(|v| encode(&v)),
        "wifi_analyze" => analyze_environment(&arguments).and_then(|v| encode(&v)),
        "wifi_history" => {
            let within = arguments
                .get("within_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(3600);
            let max = arguments
                .get("max_events")
                .and_then(Value::as_u64)
                .unwrap_or(200)
                .min(2000) as usize;

            beacontrail::events::recent(max, Some(within)).and_then(|events| {
                let verdict = beacontrail::events::detect(&events);
                let include = arguments
                    .get("include_events")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                encode(&json!({
                    "window_seconds": within,
                    "event_count": events.len(),
                    "verdict": verdict,
                    "events": if include { serde_json::to_value(&events)? } else { Value::Null },
                }))
            })
        }
        "wifi_sample" => {
            let duration = arguments
                .get("duration_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(20);
            let interval = arguments
                .get("interval_ms")
                .and_then(Value::as_u64)
                .unwrap_or(1000);
            wlan::sample::sample_connection(duration, interval).and_then(|run| encode(&run))
        }
        other => {
            return Err(RpcError {
                code: METHOD_NOT_FOUND,
                message: format!("unknown tool: {other}"),
            })
        }
    };

    Ok(match outcome {
        Ok(text) => json!({
            "content": [{ "type": "text", "text": text }],
            "isError": false
        }),
        Err(error) => json!({
            "content": [{ "type": "text", "text": error.to_string() }],
            "isError": true
        }),
    })
}

/// Read the BSS list, optionally forcing a scan first.
///
/// Windows will happily hand back an empty cache — the radio may never have
/// scanned since boot, or previous results aged out. An empty first read is
/// therefore retried once behind a real scan instead of being reported as "no
/// networks", which an agent would repeat as a factual claim about the
/// environment.
fn collect_networks(arguments: &Value) -> anyhow::Result<Value> {
    let full = arguments.get("detail").and_then(Value::as_str) == Some("full");
    let mut refreshed = arguments
        .get("refresh_scan")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if refreshed {
        // A refused scan is not fatal: the cached list is still worth returning.
        let _ = wlan::bss::request_scan();
        std::thread::sleep(SCAN_SETTLE);
    }

    let mut entries = wlan::bss::bss_list()?;

    if entries.is_empty() && !refreshed {
        let _ = wlan::bss::request_scan();
        std::thread::sleep(SCAN_SETTLE);
        entries = wlan::bss::bss_list()?;
        refreshed = true;
    }

    let networks = if full {
        serde_json::to_value(&entries)?
    } else {
        serde_json::to_value(entries.iter().map(BssSummary::from).collect::<Vec<_>>())?
    };

    Ok(json!({
        "count": entries.len(),
        "refreshed": refreshed,
        "detail": if full { "full" } else { "summary" },
        "networks": networks,
    }))
}

/// Reduce the environment to findings rather than records.
fn analyze_environment(arguments: &Value) -> anyhow::Result<Value> {
    if arguments
        .get("refresh_scan")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let _ = wlan::bss::request_scan();
        std::thread::sleep(SCAN_SETTLE);
    }

    let entries = wlan::bss::bss_list()?;
    let status = wlan::wifi_status().unwrap_or_default();
    let connection = status.iter().find_map(|entry| entry.connection.as_ref());

    Ok(serde_json::to_value(wlan::analyze::analyze(
        &entries, connection,
    ))?)
}

/// Compact, not pretty-printed: these payloads go into a model's context, where
/// indentation is pure token cost. The BSS list roughly halves.
fn encode<T: Serialize>(value: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn success_response(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_response(id: Value, code: i64, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(line: &str) -> Value {
        serde_json::from_str(&handle_line(line).expect("expected a response")).unwrap()
    }

    #[test]
    fn initialize_reports_protocol_and_tool_capability() {
        let out = response(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
        assert_eq!(out["id"], 1);
        assert_eq!(out["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(out["result"]["serverInfo"]["name"], "beacontrail");
        assert!(out["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn notifications_get_no_reply() {
        assert!(handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
    }

    #[test]
    fn tools_list_exposes_only_read_only_tools() {
        let out = response(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let tools = out["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        // Exact, not a subset: a tool appearing here unnoticed is the failure
        // mode this test exists to catch.
        assert_eq!(
            names,
            vec![
                "wifi_status",
                "wifi_networks",
                "wifi_analyze",
                "wifi_history",
                "wifi_sample",
                "wifi_scan"
            ]
        );

        // Nothing that reads secrets or mutates the adapter may ever appear here.
        for forbidden in [
            "wifi_profile_secret",
            "scan_identity_apply",
            "local_network_scan",
        ] {
            assert!(
                !names.contains(&forbidden),
                "{forbidden} must not be exposed"
            );
        }
        // Every tool must advertise an object schema.
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn unknown_method_is_a_jsonrpc_error() {
        let out = response(r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#);
        assert_eq!(out["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn unknown_tool_is_a_jsonrpc_error() {
        let out =
            response(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope"}}"#);
        assert_eq!(out["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn malformed_json_reports_a_parse_error() {
        let out = response("{ not json");
        assert_eq!(out["error"]["code"], PARSE_ERROR);
        assert_eq!(out["id"], Value::Null);
    }

    #[test]
    fn initialize_declares_the_resources_capability() {
        let out = response(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
        let resources = &out["result"]["capabilities"]["resources"];
        assert!(resources.is_object());
        // Declaring either would oblige us to implement subscribe/unsubscribe
        // or push list_changed notifications.
        assert_eq!(resources["subscribe"], false);
        assert_eq!(resources["listChanged"], false);
    }

    #[test]
    fn resources_list_returns_the_fixed_table() {
        let out = response(r#"{"jsonrpc":"2.0","id":2,"method":"resources/list"}"#);
        let resources = out["result"]["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 4);

        for resource in resources {
            // uri and name are the only required members of a Resource.
            assert!(resource["uri"]
                .as_str()
                .unwrap()
                .starts_with("beacontrail://"));
            assert!(resource["name"].is_string());
        }
        // Never paginate a fixed table, and never send a null cursor.
        assert!(out["result"].get("nextCursor").is_none());
    }

    #[test]
    fn templates_list_is_answered_rather_than_rejected() {
        let out = response(r#"{"jsonrpc":"2.0","id":3,"method":"resources/templates/list"}"#);
        assert_eq!(
            out["result"]["resourceTemplates"].as_array().unwrap().len(),
            0
        );
        assert!(out.get("error").is_none());
    }

    #[test]
    fn unknown_resource_uri_is_a_dedicated_error_code() {
        let out = response(
            r#"{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"beacontrail://bogus"}}"#,
        );
        // -32002, not -32601 and not -32602.
        assert_eq!(out["error"]["code"], RESOURCE_NOT_FOUND);
    }

    #[test]
    fn a_uri_that_merely_contains_a_known_one_is_rejected() {
        // Guards the exact-match rule: no substring matching, no path joining.
        let out = response(
            r#"{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"beacontrail://report/latest/../evil"}}"#,
        );
        assert_eq!(out["error"]["code"], RESOURCE_NOT_FOUND);
    }

    #[test]
    fn leading_utf8_bom_is_tolerated() {
        let out = response("\u{feff}{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}");
        assert_eq!(out["id"], 9);
        assert!(out.get("error").is_none());
    }

    #[test]
    fn request_without_method_is_invalid() {
        let out = response(r#"{"jsonrpc":"2.0","id":5}"#);
        assert_eq!(out["error"]["code"], INVALID_REQUEST);
    }
}
