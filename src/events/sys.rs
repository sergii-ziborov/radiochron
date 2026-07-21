//! Hand-written runtime-loaded FFI to `wevtapi.dll`.
//!
//! Four symbols, resolved through the same system32-only `LoadLibraryExW`/`GetProcAddress`
//! helper the WLAN module uses. `libwevtapi.a` does not ship with the Rust
//! toolchain, so a link-time dependency would reintroduce the build-tooling
//! problem this project exists to avoid.
//!
//! Signatures and constants below are verified against Microsoft's `winevt.h`
//! documentation.

use std::ffi::c_void;
use std::sync::OnceLock;

use crate::dll::{load_system_library, symbol};

// EVT_QUERY_FLAGS.
const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
/// Without this, one bad channel aborts the whole query.
const EVT_QUERY_TOLERATE_QUERY_ERRORS: u32 = 0x1000;

/// EVT_RENDER_FLAGS::EvtRenderEventXml. Context MUST be NULL with this flag.
const EVT_RENDER_EVENT_XML: u32 = 1;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;

const INFINITE: u32 = 0xFFFF_FFFF;
/// How many event handles to pull per `EvtNext`.
const BATCH: usize = 32;

type EvtQueryFn =
    unsafe extern "system" fn(*mut c_void, *const u16, *const u16, u32) -> *mut c_void;
type EvtNextFn =
    unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void, u32, u32, *mut u32) -> i32;
type EvtRenderFn = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    u32,
    u32,
    *mut c_void,
    *mut u32,
    *mut u32,
) -> i32;
type EvtCloseFn = unsafe extern "system" fn(*mut c_void) -> i32;

struct EvtApi {
    query: EvtQueryFn,
    next: EvtNextFn,
    render: EvtRenderFn,
    close: EvtCloseFn,
}

static API: OnceLock<Option<EvtApi>> = OnceLock::new();

fn api() -> anyhow::Result<&'static EvtApi> {
    API.get_or_init(|| unsafe { load() })
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("wevtapi.dll unavailable: cannot read the Windows event log")
        })
}

unsafe fn load() -> Option<EvtApi> {
    let module = load_system_library("wevtapi.dll")?;

    macro_rules! sym {
        ($name:expr, $ty:ty) => {
            std::mem::transmute::<*mut c_void, $ty>(symbol(module, $name)?)
        };
    }

    Some(EvtApi {
        query: sym!(c"EvtQuery", EvtQueryFn),
        next: sym!(c"EvtNext", EvtNextFn),
        render: sym!(c"EvtRender", EvtRenderFn),
        close: sym!(c"EvtClose", EvtCloseFn),
    })
}

fn last_error() -> u32 {
    // Read immediately; any intervening FFI call can clobber it.
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Query a channel and return up to `max` rendered event XML documents, newest
/// first.
///
/// Filtering is pushed into the XPath query so the event-log service evaluates
/// it against the indexed log rather than us discarding records in Rust.
pub fn query_xml(
    channel: &str,
    max: usize,
    within_seconds: Option<u64>,
) -> anyhow::Result<Vec<String>> {
    if max == 0 {
        return Ok(Vec::new());
    }

    let api = api()?;

    // timediff() takes FILETIME and yields milliseconds; omitting the second
    // argument means "against current system time".
    let query = match within_seconds {
        Some(seconds) => {
            let milliseconds = seconds
                .checked_mul(1000)
                .ok_or_else(|| anyhow::anyhow!("event history window is too large"))?;
            format!("*[System[TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]")
        }
        None => "*".to_string(),
    };

    let channel_w = wide(channel);
    let query_w = wide(&query);

    let handle = unsafe {
        (api.query)(
            std::ptr::null_mut(),
            channel_w.as_ptr(),
            query_w.as_ptr(),
            EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION | EVT_QUERY_TOLERATE_QUERY_ERRORS,
        )
    };

    if handle.is_null() {
        // Never let a permission failure render as "no events": for a
        // diagnostic tool that reads as "no problems", which is the worst
        // possible inversion.
        return Err(match last_error() {
            ERROR_ACCESS_DENIED => anyhow::anyhow!(
                "access denied reading {channel}. Run RadioChron elevated to read the WLAN event log."
            ),
            ERROR_EVT_CHANNEL_NOT_FOUND => {
                anyhow::anyhow!("event channel not found: {channel}")
            }
            code => anyhow::anyhow!("EvtQuery failed on {channel} (error {code})"),
        });
    }

    let _query_guard = Handle(handle, api);
    let mut documents = Vec::new();
    let mut batch: [*mut c_void; BATCH] = [std::ptr::null_mut(); BATCH];

    while documents.len() < max {
        let mut returned: u32 = 0;
        let ok = unsafe {
            (api.next)(
                handle,
                BATCH as u32,
                batch.as_mut_ptr(),
                INFINITE,
                0, // Reserved. Must be zero.
                &mut returned,
            )
        };

        if ok == 0 {
            let code = last_error();
            // Normal termination, not a failure.
            if code == ERROR_NO_MORE_ITEMS {
                break;
            }
            anyhow::bail!(
                "EvtNext failed on {channel} after {} rendered events (error {code})",
                documents.len()
            );
        }

        // Own every handle in the returned batch before doing anything that can
        // fail or hit the caller's limit. This is important when, for example,
        // 8 records are still needed from a 32-handle batch: the other 24 must
        // be closed too.
        let guards: Vec<Handle> = batch
            .iter()
            .take(returned as usize)
            .copied()
            .map(|event| Handle(event, api))
            .collect();

        for event in &guards {
            if documents.len() >= max {
                continue;
            }
            documents.push(render(api, event.0)?);
        }

        if (returned as usize) < BATCH {
            break;
        }
    }

    Ok(documents)
}

/// Two-call render: size, then fill.
///
/// `BufferSize` and `BufferUsed` are both in BYTES, not WCHARs — the single most
/// common bug against this API. Note also that the MSDN sample checks
/// `GetLastError()` after the successful second call, where it still holds the
/// stale `ERROR_INSUFFICIENT_BUFFER` from the sizing call; that structure fails
/// on every success. Key off the returned BOOL instead.
fn render(api: &EvtApi, event: *mut c_void) -> anyhow::Result<String> {
    let mut needed_bytes: u32 = 0;
    let mut property_count: u32 = 0;

    unsafe {
        (api.render)(
            std::ptr::null_mut(),
            event,
            EVT_RENDER_EVENT_XML,
            0,
            std::ptr::null_mut(),
            &mut needed_bytes,
            &mut property_count,
        );
    }

    let sizing_error = last_error();
    if needed_bytes == 0 || sizing_error != ERROR_INSUFFICIENT_BUFFER {
        anyhow::bail!(
            "EvtRender sizing failed (error {sizing_error}, needed {needed_bytes} bytes)"
        );
    }

    // Bytes to UTF-16 code units, rounding up.
    let mut buffer: Vec<u16> = vec![0; needed_bytes as usize / 2 + 1];
    let ok = unsafe {
        (api.render)(
            std::ptr::null_mut(),
            event,
            EVT_RENDER_EVENT_XML,
            needed_bytes,
            buffer.as_mut_ptr().cast(),
            &mut needed_bytes,
            &mut property_count,
        )
    };

    if ok == 0 {
        let code = last_error();
        anyhow::bail!("EvtRender failed (error {code})");
    }

    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..end]))
}

/// Closes any `EVT_HANDLE`. Leaking these leaks kernel-side event-log state,
/// not merely process memory.
struct Handle(*mut c_void, &'static EvtApi);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                (self.1.close)(self.0);
            }
        }
    }
}
