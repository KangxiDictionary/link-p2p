//! Best-effort Windows Application Event Log writes for the TUN service.
//!
//! SCM-started processes often have no useful stderr; failures that only
//! `eprintln!` are invisible in Services.msc / Event Viewer. Registration of
//! a message DLL is optional — insertion strings still appear in Event Viewer
//! even when the source is unregistered.

#![allow(unsafe_code)]

use std::ptr;

use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

const SOURCE: &str = "link-p2p-tun";

#[derive(Debug, Clone, Copy)]
pub enum Level {
    Info,
    Warn,
    Error,
}

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn event_type(level: Level) -> REPORT_EVENT_TYPE {
    match level {
        Level::Info => EVENTLOG_INFORMATION_TYPE,
        Level::Warn => EVENTLOG_WARNING_TYPE,
        Level::Error => EVENTLOG_ERROR_TYPE,
    }
}

/// Write `message` to the Application log under source [`SOURCE`].
///
/// Returns `Err` when RegisterEventSource / ReportEvent fails (restricted
/// token, full log, etc.). Callers that still have a console should surface
/// that; under SCM the original failure message is already in `message`.
pub fn report(level: Level, message: &str) -> Result<(), String> {
    let source = encode_wide(SOURCE);
    let handle = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return Err("RegisterEventSourceW failed".into());
    }
    // RegisterEventSourceW returns a HANDLE closed with DeregisterEventSource.
    struct EventSource(*mut core::ffi::c_void);
    impl Drop for EventSource {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = DeregisterEventSource(self.0);
                }
            }
        }
    }
    let _guard = EventSource(handle);

    let wide = encode_wide(message);
    let strings = [wide.as_ptr()];
    // Event ID 0 + no message file → Event Viewer still shows the insertion string.
    let ok = unsafe {
        ReportEventW(
            handle,
            event_type(level),
            0,
            0,
            ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            ptr::null(),
        )
    };
    if ok == FALSE {
        return Err("ReportEventW failed".into());
    }
    Ok(())
}

pub fn info(message: &str) -> Result<(), String> {
    report(Level::Info, message)
}

pub fn warn(message: &str) -> Result<(), String> {
    report(Level::Warn, message)
}

pub fn error(message: &str) -> Result<(), String> {
    report(Level::Error, message)
}
