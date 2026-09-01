//! Windows Service Control Manager integration for `link-p2p tun`.
//!
//! Install registers a LocalSystem service whose `ExecutablePath` includes
//! `--windows-service`. Process start under SCM hits [`run_dispatcher`], which
//! completes the SCM handshake and then runs the same supervised TUN worker as
//! `tun up --foreground --system`.

#![allow(unsafe_code)]

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::exit;
use crate::i18n::tr;
use crate::style::{self, ColorMode};
use crate::tun_ctl::{self, RuntimeMode};
use crate::tun_daemon::{self, SupervisedUpOpts};
use crate::tun_service::InstallOpts;
use crate::win_eventlog;
use crate::Ui;

/// SCM service name (not the display name).
pub const SERVICE_NAME: &str = "link-p2p-tun";
pub const SERVICE_DISPLAY: &str = "link-p2p TUN mesh daemon";

/// How often the service refreshes `SERVICE_RUNNING` so SCM does not treat a
/// hung worker as "still fine forever" without a heartbeat.
const STATUS_KEEPALIVE: Duration = Duration::from_secs(30);

define_windows_service!(ffi_service_main, service_main);

/// Block in `StartServiceCtrlDispatcher` until the service stops.
pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow::anyhow!("StartServiceCtrlDispatcher: {e}"))
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service_body() {
        let _ = win_eventlog::error(&format!("link-p2p-tun service failed: {e:#}"));
    }
}

fn running_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

fn stopped_status(win32_exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(win32_exit),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

fn run_service_body() -> Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| anyhow::anyhow!("RegisterServiceCtrlHandler: {e}"))?;

    status_handle
        .set_service_status(running_status())
        .map_err(|e| anyhow::anyhow!("SetServiceStatus(Running): {e}"))?;

    let _ = win_eventlog::info("link-p2p-tun service entered Running state");

    // Fail fast on a bad SDDL constant before opening the control pipe.
    crate::win_pipe::validate_system_pipe_sddl()
        .context(tr!("validating system named-pipe SDDL"))?;

    let opts = parse_service_up_opts()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime for Windows TUN service")?;

    let ui = Ui {
        quiet: true,
        stderr_only: true,
    };
    let styler = style::apply_color_mode(ColorMode::Never);

    let worker = rt.spawn(async move {
        tun_daemon::run_supervised_foreground(opts, ui, styler).await
    });

    // Keep-alive: refresh SERVICE_RUNNING every STATUS_KEEPALIVE until stop
    // or the worker finishes (crash / clean exit). Without this, SCM can sit
    // on a dead process until its own wait hint expires.
    let mut stop_requested = false;
    loop {
        match stop_rx.recv_timeout(STATUS_KEEPALIVE) {
            Ok(()) => {
                stop_requested = true;
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = status_handle.set_service_status(running_status());
                if worker.is_finished() {
                    let _ = win_eventlog::warn(
                        "link-p2p-tun worker exited before Stop; reporting Stopped to SCM",
                    );
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop_requested = true;
                break;
            }
        }
    }

    if stop_requested {
        let _ = win_eventlog::info("link-p2p-tun received Stop/Shutdown; draining control plane");
        rt.block_on(async {
            let _ = tun_daemon::send_ctl_shutdown(RuntimeMode::System).await;
        });
    }

    let worker_res = rt.block_on(async { worker.await });
    let exit_win32 = match &worker_res {
        Ok(Ok(())) => 0u32,
        Ok(Err(e)) => exit::code_from(e) as u32,
        Err(_) => exit::OTHER as u32,
    };
    let _ = status_handle.set_service_status(stopped_status(exit_win32));

    match worker_res {
        Ok(Ok(())) => {
            let _ = win_eventlog::info("link-p2p-tun service stopped cleanly");
            Ok(())
        }
        Ok(Err(e)) => {
            let _ = win_eventlog::error(&format!("link-p2p-tun worker error: {e:#}"));
            Err(e)
        }
        Err(e) => {
            let err = anyhow::anyhow!("service worker join: {e}");
            let _ = win_eventlog::error(&format!("{err:#}"));
            Err(err)
        }
    }
}

fn parse_service_up_opts() -> Result<SupervisedUpOpts> {
    let mut role = "hub".to_string();
    let mut to: Option<String> = None;
    let mut identity = tun_ctl::default_system_identity_path();
    let mut mtu: u16 = 1280;
    let mut args = std::env::args().skip_while(|a| a != "tun").skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--role" => {
                if let Some(v) = args.next() {
                    role = v;
                }
            }
            "--to" => to = args.next(),
            "--identity" => {
                if let Some(v) = args.next() {
                    identity = std::path::PathBuf::from(v);
                }
            }
            "--mtu" => {
                if let Some(v) = args.next() {
                    mtu = v.parse().unwrap_or(1280);
                }
            }
            _ => {}
        }
    }
    tun_ctl::verify_identity_parent_writable(&identity)
        .context(tr!("verifying system identity directory is writable"))?;
    role = tun_daemon::resolve_up_role(Some(&role), to.as_deref())?;
    let passphrase = std::env::var("LINK_P2P_PASSPHRASE")
        .ok()
        .filter(|p| !p.is_empty());
    if let Some(p) = &passphrase {
        crate::validate_passphrase(p)?;
    }
    let secret_key = crate::load_or_create_secret_key(&identity, passphrase.as_deref())
        .context(tr!("loading/creating persistent identity"))?;

    Ok(SupervisedUpOpts {
        role,
        to,
        tun_ip: None,
        tun_ip6: None,
        mtu,
        allow: None,
        to_addr: vec![],
        secret_key,
        relays: vec![],
        relay_only: false,
        no_n0_relays: false,
        tune: crate::TransportTune::default(),
        keepalive: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(30),
    })
}

/// Register and start the LocalSystem service.
pub fn install_scm(exe: &std::path::Path, opts: &InstallOpts) -> Result<()> {
    crate::win_pipe::validate_system_pipe_sddl()
        .context(tr!("validating system named-pipe SDDL"))?;
    tun_ctl::verify_identity_parent_writable(&opts.identity)
        .context(tr!("verifying system identity directory is writable"))?;

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| anyhow::anyhow!("OpenSCManager: {e}"))?;

    let mut launch_arguments = vec![
        OsString::from("tun"),
        OsString::from("up"),
        OsString::from("--foreground"),
        OsString::from("--system"),
        OsString::from("--windows-service"),
        OsString::from("--role"),
        OsString::from(&opts.role),
        OsString::from("--identity"),
        opts.identity.as_os_str().to_os_string(),
    ];
    if let Some(to) = &opts.to {
        launch_arguments.push(OsString::from("--to"));
        launch_arguments.push(OsString::from(to));
    }

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments,
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    if let Ok(existing) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        let _ = existing.stop();
        wait_until_stopped(&existing)?;
        existing
            .delete()
            .map_err(|e| anyhow::anyhow!("DeleteService: {e}"))?;
        std::thread::sleep(Duration::from_millis(500));
    }

    let service = manager
        .create_service(
            &info,
            ServiceAccess::START | ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| anyhow::anyhow!("CreateService: {e}"))?;

    service
        .set_description("link-p2p TUN mesh daemon (hub/spoke over QUIC datagrams)")
        .ok();
    service
        .start(&[] as &[&std::ffi::OsStr])
        .map_err(|e| anyhow::anyhow!("StartService: {e}"))?;
    Ok(())
}

/// Stop and delete the service (identity file is kept).
pub fn uninstall_scm() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| anyhow::anyhow!("OpenSCManager: {e}"))?;

    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let _ = service.stop();
    wait_until_stopped(&service)?;
    service
        .delete()
        .map_err(|e| anyhow::anyhow!("DeleteService: {e}"))?;
    Ok(())
}

fn wait_until_stopped(service: &windows_service::service::Service) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = service
            .query_status()
            .map_err(|e| anyhow::anyhow!("QueryServiceStatus: {e}"))?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(tr!("timed out waiting for link-p2p-tun service to stop"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// True when the current process token is elevated (admin).
pub fn process_is_elevated() -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == FALSE || token.is_null() {
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
    let _c = Close(token);

    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
    };
    ok != FALSE && elev.TokenIsElevated != 0
}

pub fn require_admin() -> Result<()> {
    if process_is_elevated() {
        return Ok(());
    }
    bail!(exit::coded(
        exit::USAGE,
        anyhow::anyhow!(tr!(
            "this command must be run as Administrator (elevated PowerShell / cmd)"
        )),
    ));
}

/// Build the launch argument vector (pure — for tests).
pub fn launch_arguments(opts: &InstallOpts) -> Vec<String> {
    let mut v = vec![
        "tun".into(),
        "up".into(),
        "--foreground".into(),
        "--system".into(),
        "--windows-service".into(),
        "--role".into(),
        opts.role.clone(),
        "--identity".into(),
        opts.identity.display().to_string(),
    ];
    if let Some(to) = &opts.to {
        v.push("--to".into());
        v.push(to.clone());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn launch_arguments_include_windows_service_flag() {
        let args = launch_arguments(&InstallOpts {
            role: "hub".into(),
            to: None,
            identity: PathBuf::from(r"C:\ProgramData\link-p2p\identity.key"),
            service_user: "link-p2p".into(),
            identity_fallback: None,
        });
        assert!(args.iter().any(|a| a == "--windows-service"));
        assert!(args.iter().any(|a| a == "--system"));
        assert!(args.iter().any(|a| a == "--foreground"));
    }

    /// Manual / CI-on-Windows: needs Administrator + `wintun.dll` beside the
    /// test binary. Run with `cargo test -p link-p2p -- --ignored`.
    #[test]
    #[ignore = "needs Administrator + wintun.dll beside the executable"]
    fn ignored_system_pipe_sddl_and_identity_preflight() {
        crate::win_pipe::validate_system_pipe_sddl().expect("SDDL");
        // Writable only when elevated under ProgramData; soft-fail on CI.
        let _ = tun_ctl::verify_identity_parent_writable(&tun_ctl::default_system_identity_path());
    }
}
