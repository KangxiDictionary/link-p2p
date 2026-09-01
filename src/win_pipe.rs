//! Windows named-pipe helpers for TUN control (`LPC1` over `\\.\pipe\…`).
//!
//! Tokio's safe [`ServerOptions`](tokio::net::windows::named_pipe::ServerOptions)
//! cannot set a custom DACL. System mode therefore creates the pipe with
//! `CreateNamedPipeW` + SDDL, then hands the handle to tokio via
//! [`NamedPipeServer::from_raw_handle`].

#![allow(unsafe_code)]

use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::ptr;

use anyhow::{bail, Context, Result};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, BOOL, ERROR_PIPE_BUSY, FALSE, HANDLE, INVALID_HANDLE_VALUE, TRUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CheckTokenMembership, FreeSid, GetTokenInformation, RevertToSelf,
    TokenElevation, SECURITY_ATTRIBUTES, SECURITY_NT_AUTHORITY, TOKEN_ELEVATION, TOKEN_QUERY, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::{
    DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID, SECURITY_LOCAL_SYSTEM_RID,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::tun_ctl::WINDOWS_SYSTEM_PIPE_SDDL;

const PIPE_BUFFER: u32 = 64 * 1024;

/// SDDL applied to the system control pipe (same as [`WINDOWS_SYSTEM_PIPE_SDDL`]).
pub fn system_pipe_sddl() -> &'static str {
    WINDOWS_SYSTEM_PIPE_SDDL
}

/// Parse [`WINDOWS_SYSTEM_PIPE_SDDL`] with the Win32 SDDL API so a typo fails
/// at install/start instead of at the first `CreateNamedPipeW`.
pub fn validate_system_pipe_sddl() -> Result<()> {
    let sddl = encode_wide(WINDOWS_SYSTEM_PIPE_SDDL);
    let mut sd: *mut core::ffi::c_void = ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    };
    if ok == FALSE || sd.is_null() {
        bail!(
            "invalid WINDOWS_SYSTEM_PIPE_SDDL (ConvertStringSecurityDescriptor failed): {}",
            WINDOWS_SYSTEM_PIPE_SDDL
        );
    }
    unsafe {
        LocalFree(sd as _);
    }
    Ok(())
}

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Create one overlapping named-pipe server instance.
///
/// When `system_acl` is true, applies [`WINDOWS_SYSTEM_PIPE_SDDL`] so any local
/// user can connect (read/write) while SYSTEM/Administrators retain full control.
pub fn create_server_instance(pipe_name: &str, system_acl: bool) -> Result<OwnedHandle> {
    let wide = encode_wide(pipe_name);
    let mut sd: *mut core::ffi::c_void = ptr::null_mut();
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: FALSE,
    };
    let sa_ptr: *const SECURITY_ATTRIBUTES = if system_acl {
        let sddl = encode_wide(WINDOWS_SYSTEM_PIPE_SDDL);
        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW writes a
        // LocalAlloc'd descriptor into `sd` on success; we free it after CreateNamedPipeW.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == FALSE || sd.is_null() {
            bail!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
        }
        sa.lpSecurityDescriptor = sd;
        &sa
    } else {
        ptr::null()
    };

    // SAFETY: `wide` is a valid NUL-terminated PCWSTR; `sa_ptr` is either null
    // (default ACL) or points at `sa` whose descriptor outlives this call.
    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            sa_ptr,
        )
    };

    if system_acl && !sd.is_null() {
        // SAFETY: `sd` was allocated by ConvertStringSecurityDescriptor… above.
        unsafe {
            LocalFree(sd as _);
        }
    }

    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("CreateNamedPipeW({pipe_name})"));
    }

    // SAFETY: CreateNamedPipeW returned a fresh owned handle on success.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Open a client connection to an existing named pipe (sync; usually instant).
pub fn connect_client(pipe_name: &str) -> Result<NamedPipeClient> {
    ClientOptions::new()
        .open(pipe_name)
        .with_context(|| format!("opening named pipe client {pipe_name}"))
}

/// Wrap a raw pipe handle as a tokio [`NamedPipeServer`].
pub fn into_server(handle: OwnedHandle) -> Result<NamedPipeServer> {
    let raw = handle.into_raw_handle();
    // SAFETY: `raw` is a valid CreateNamedPipeW handle; tokio takes ownership.
    unsafe { NamedPipeServer::from_raw_handle(raw) }
        .context("NamedPipeServer::from_raw_handle")
}

/// Whether the connected client is an elevated administrator (or LocalSystem).
///
/// Impersonates the pipe client, checks Administrators / LocalSystem membership
/// and `TokenElevation`, then always `RevertToSelf`. Fails closed on any error.
///
/// # Call-site invariant (no yield between check and privileged op)
///
/// The impersonated token describes the client of **this** pipe instance at
/// call time. Callers must treat `peer_is_admin` + the privileged control
/// action as a single synchronous critical section: do not `.await` between
/// them (another accept/handshake must not run on the same logical trust
/// decision). Current ctl handlers honor this; keep it that way.
pub fn peer_is_admin(server: &NamedPipeServer) -> bool {
    let handle = server.as_raw_handle() as HANDLE;
    // SAFETY: `handle` is a live named-pipe server connected to a client.
    if unsafe { ImpersonateNamedPipeClient(handle) } == FALSE {
        return false;
    }

    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: paired with ImpersonateNamedPipeClient above.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }
    let _revert = Revert;

    token_is_admin_or_system()
}

fn token_is_admin_or_system() -> bool {
    // Three overlapping checks (fail closed / prefer false negatives):
    // 1) BUILTIN\Administrators membership — elevated admin tokens.
    // 2) LocalSystem — service accounts often lack the Administrators SID.
    // 3) TokenElevation — UAC filtered tokens may still list Administrators
    //    as Deny-Only (so (1) is false) while elevation is the real signal;
    //    conversely, some service contexts elevate without matching (1)/(2)
    //    the way we expect. Doing all three is deliberate redundancy.
    if sid_member_of_current_token(admin_sid) {
        return true;
    }
    if sid_member_of_current_token(local_system_sid) {
        return true;
    }
    token_is_elevated()
}

fn admin_sid(out: &mut PSID) -> bool {
    // SAFETY: AllocateAndInitializeSid writes a heap SID we FreeSid later.
    unsafe {
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            out,
        ) != FALSE
    }
}

fn local_system_sid(out: &mut PSID) -> bool {
    unsafe {
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            1,
            SECURITY_LOCAL_SYSTEM_RID as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            out,
        ) != FALSE
    }
}

fn sid_member_of_current_token(make_sid: fn(&mut PSID) -> bool) -> bool {
    let mut sid: PSID = ptr::null_mut();
    if !make_sid(&mut sid) || sid.is_null() {
        return false;
    }
    struct FreePs(PSID);
    impl Drop for FreePs {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: SID from AllocateAndInitializeSid.
                unsafe {
                    FreeSid(self.0);
                }
            }
        }
    }
    let _free = FreePs(sid);

    let mut is_member: BOOL = FALSE;
    // NULL token → use the impersonation token of this thread.
    let ok = unsafe { CheckTokenMembership(ptr::null_mut(), sid, &mut is_member) };
    ok != FALSE && is_member != FALSE
}

fn token_is_elevated() -> bool {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: OpenThreadToken on the impersonated thread.
    let opened = unsafe {
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &mut token)
    };
    if opened == FALSE || token.is_null() {
        return false;
    }
    struct Close(HANDLE);
    impl Drop for Close {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
    let _close = Close(token);

    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret_len = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    ok != FALSE && elev.TokenIsElevated != 0
}

/// True when `open` failed because every pipe instance is busy (retryable).
pub fn is_pipe_busy(err: &anyhow::Error) -> bool {
    err.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .and_then(|e| e.raw_os_error())
            == Some(ERROR_PIPE_BUSY as i32)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_pipe_sddl_matches_expected() {
        assert_eq!(
            system_pipe_sddl(),
            "D:(A;;GRGW;;;BU)(A;;GA;;;SY)(A;;GA;;;BA)"
        );
        assert_eq!(system_pipe_sddl(), WINDOWS_SYSTEM_PIPE_SDDL);
    }

    #[test]
    fn system_pipe_sddl_parses_on_windows() {
        validate_system_pipe_sddl().expect("hard-coded SDDL must parse");
    }
}
