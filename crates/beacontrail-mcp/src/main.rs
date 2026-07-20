//! BeaconTrail MCP server.
//!
//! A thin transport shell over the `beacontrail` library: this crate owns the
//! protocol and the report rendering, and nothing else. All collection and
//! analysis lives in the library, so an IoT agent or a CLI can use the same
//! engine without dragging JSON-RPC along.
//!
//! Speaks the Model Context Protocol over stdio. Register it with an MCP client
//! (Claude Code, Claude Desktop, Codex, …) by pointing the client at this
//! binary; no arguments are required.
//!
//! On the stdio transport stdout carries JSON-RPC frames and nothing else, so
//! all diagnostics must go to stderr.

#[cfg(windows)]
mod mcp;
#[cfg(windows)]
mod report;

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    mcp::serve_stdio()
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("BeaconTrail requires Windows (it talks to wlanapi.dll).")
}
