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

use crate::wlan;
use crate::wlan::bss::BssSummary;

/// MCP revision this server implements.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Dwell time after asking the driver to scan before reading the BSS list.
/// Windows reports scan completion asynchronously.
const SCAN_SETTLE: Duration = Duration::from_secs(4);

// JSON-RPC 2.0 error codes.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;

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
        other => Err(RpcError {
            code: METHOD_NOT_FOUND,
            message: format!("unknown method: {other}"),
        }),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
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
            "name": "wifi_scan",
            "description": "Ask every WLAN interface to perform a fresh scan. Returns how many \
                            interfaces accepted the request. Results arrive asynchronously — read \
                            them with wifi_networks a few seconds later. Emits no network traffic \
                            beyond a standard Wi-Fi scan.",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ])
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
        assert_eq!(names, vec!["wifi_status", "wifi_networks", "wifi_scan"]);

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
