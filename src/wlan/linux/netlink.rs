//! Minimal Generic Netlink transport for `nl80211`.
//!
//! Socket ownership and blocking I/O are isolated from message encoding and
//! parsing so both boundaries remain small and independently testable.

mod socket;
mod wire;

pub(super) use socket::GenericSocket;
pub(super) use wire::{attributes, push_attribute, push_u32, read_u16, read_u32, read_u64};

#[cfg(test)]
mod tests;
