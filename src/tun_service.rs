//! Platform service install/uninstall for `link-p2p tun` (Layer 4).
//!
//! Linux: systemd unit. macOS: LaunchDaemon plist. Windows SCM is a follow-up.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::exit;
use crate::i18n::{tr, tr_fmt};
use crate::style::Styler;
use crate::tun_daemon;

pub const UNIT_NAME: &str = "link-p2p-tun.service";
pub const LAUNCHD_LABEL: &str = "com.link-p2p.tun";
pub const PLIST_NAME: &str = "com.link-p2p.tun.plist";
pub const DEFAULT_SERVICE_USER: &str = "link-p2p";

#[cfg(windows)]
pub const DEFAULT_IDENTITY_PATH: &str = r"C:\ProgramData\link-p2p\identity.key";
#[cfg(not(windows))]
pub const DEFAULT_IDENTITY_PATH: &str = "/etc/link-p2p/identity.key";

const MACOS_LOG_DIR: &str = "/var/log/link-p2p";

/// Options for `tun service install`.
#[derive(Debug, Clone)]
pub struct InstallOpts {
    pub role: String,
    pub to: Option<String>,
    pub identity: PathBuf,
    pub service_user: String,
    /// When the target identity is missing, copy from this path if set/exists.
    pub identity_fallback: Option<PathBuf>,
}

/// Render the systemd unit file (pure — for tests and install).
pub fn render_unit(exe: &Path, opts: &InstallOpts) -> Result<String> {
    let exe = exe.to_string_lossy();
    if exe.contains('\n') || exe.contains('"') {
        bail!(tr!("invalid executable path for systemd unit"));
    }
    let identity = opts.identity.to_string_lossy();
    if identity.contains('\n') || identity.contains('"') {
        bail!(tr!("invalid identity path for systemd unit"));
    }

    let mut exec = format!(
        "{exe} tun up --foreground --system --role {} --identity {identity}",
        opts.role
    );
    if let Some(to) = &opts.to {
        if to.contains('"') || to.contains('\n') {
            bail!(tr!("invalid --to value for systemd unit"));
        }
        exec.push_str(&format!(" --to {to}"));
    }

    Ok(format!(
        r#"# Installed by `link-p2p tun service install` — do not hand-edit; re-run install to change.
[Unit]
Description=link-p2p TUN mesh daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec}
User={user}
RuntimeDirectory=link-p2p
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"#,
        user = opts.service_user,
    ))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render a LaunchDaemon plist (pure — for tests and install).
pub fn render_plist(exe: &Path, opts: &InstallOpts) -> Result<String> {
    let exe = xml_escape(&exe.to_string_lossy());
    if exe.contains('\n') {
        bail!(tr!("invalid executable path for LaunchDaemon plist"));
    }
    let identity = xml_escape(&opts.identity.to_string_lossy());
    if identity.contains('\n') {
        bail!(tr!("invalid identity path for LaunchDaemon plist"));
    }

    let mut args = vec![
        exe,
        "tun".into(),
        "up".into(),
        "--foreground".into(),
        "--system".into(),
        "--role".into(),
        opts.role.clone(),
        "--identity".into(),
        identity,
    ];
    if let Some(to) = &opts.to {
        if to.contains('\n') {
            bail!(tr!("invalid --to value for LaunchDaemon plist"));
        }
        args.push("--to".into());
        args.push(xml_escape(to));
    }

    let args_xml: String = args
        .iter()
        .map(|a| format!("\n        <string>{a}</string>"))
        .collect();

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Installed by `link-p2p tun service install` — re-run install to change. -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir}/tun.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/tun.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        log_dir = MACOS_LOG_DIR,
    ))
}

/// Refuse service install when the binary lives in a directory users can swap.
pub fn validate_service_binary(exe: &Path) -> Result<PathBuf> {
    let exe = fs::canonicalize(exe)
        .with_context(|| tr_fmt!("resolving binary path {0}", exe.display().to_string()))?;
    check_service_binary_path(&exe)?;
    Ok(exe)
}

/// Path rules for a service binary (testable without a live file).
pub fn check_service_binary_path(path: &Path) -> Result<()> {
    let lossy = path.to_string_lossy();
    let lower = lossy.to_ascii_lowercase();

    if lower.contains("/target/debug") || lower.contains("/target/release") {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "refusing service install: binary is under a Cargo target/ directory (install a release build to /usr/local/bin or similar first)"
            )),
        ));
    }
    if lower.starts_with("/tmp/") || lower.starts_with("/var/tmp/") {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "refusing service install: binary is under /tmp (install to a system path first)"
            )),
        ));
    }
    if lower.starts_with("/home/") {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "refusing service install: binary is under /home (install to /usr/local/bin or /usr/bin first)"
            )),
        ));
    }
    if lower.starts_with("/users/") || lower.contains(r"\users\") {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "refusing service install: binary is under /Users (install to /usr/local/bin first)"
            )),
        ));
    }
    if lower.contains(r"\appdata\") || lower.contains("/appdata/") {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "refusing service install: binary is under AppData (install to Program Files first)"
            )),
        ));
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() && lossy.starts_with(&home) {
            bail!(exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!(
                    "refusing service install: binary is under your home directory (install to a system path first)"
                )),
            ));
        }
    }

    let parent = path
        .parent()
        .context(tr!("binary path has no parent directory"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent.exists() {
            let mode = fs::metadata(parent)
                .with_context(|| {
                    tr_fmt!("stat binary directory {0}", parent.display().to_string())
                })?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o022 != 0 {
                bail!(exit::coded(
                    exit::USAGE,
                    anyhow::anyhow!(tr_fmt!(
                        "refusing service install: directory {0} is group/world-writable (any local user could replace the binary the service runs as root/CAP_NET_ADMIN)",
                        parent.display().to_string()
                    )),
                ));
            }
        }
    }

    Ok(())
}

fn unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system").join(UNIT_NAME)
}

#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(PLIST_NAME)
}

fn require_elevated() -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if !nix::unistd::geteuid().is_root() {
            bail!(exit::coded(
                exit::USAGE,
                anyhow::anyhow!(tr!(
                    "this command must be run as root (try: sudo link-p2p tun service …)"
                )),
            ));
        }
        return Ok(());
    }
    #[cfg(windows)]
    {
        return crate::win_service::require_admin();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        bail!(exit::coded(
            exit::USAGE,
            anyhow::anyhow!(tr!(
                "tun service install is not supported on this platform yet"
            )),
        ));
    }
}

fn run_ok(cmd: &mut Command, what: &str) -> Result<()> {
    let out = cmd.output().with_context(|| tr_fmt!("running {0}", what))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    bail!(tr_fmt!(
        "{0} failed (exit {1}): {2}{3}",
        what,
        out.status.code().unwrap_or(-1),
        stderr.trim(),
        if stdout.trim().is_empty() {
            String::new()
        } else {
            format!(" ({})", stdout.trim())
        }
    ));
}

fn ensure_system_user(user: &str) -> Result<()> {
    let check = Command::new("id").arg("-u").arg(user).output();
    if let Ok(out) = check {
        if out.status.success() {
            return Ok(());
        }
    }
    run_ok(
        Command::new("useradd")
            .args([
                "--system",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                user,
            ]),
        &tr_fmt!("creating system user {0}", user),
    )
}

fn bootstrap_identity(target: &Path, fallback: Option<&Path>, _service_user: &str) -> Result<()> {
    if target.exists() {
        return Ok(());
    }
    if let Some(src) = fallback {
        if src.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    tr_fmt!("creating {0}", parent.display().to_string())
                })?;
            }
            fs::copy(src, target).with_context(|| {
                tr_fmt!(
                    "copying identity {0} -> {1}",
                    src.display().to_string(),
                    target.display().to_string()
                )
            })?;
            return Ok(());
        }
    }
    bail!(exit::coded(
        exit::USAGE,
        anyhow::anyhow!(tr_fmt!(
            "identity key not found at {0}; create it or re-run install after copying your key (e.g. from ~/.config/link-p2p/identity.key)",
            target.display().to_string()
        )),
    ));
}

#[cfg(unix)]
fn secure_identity_for_service(path: &Path, service_user: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)
        .with_context(|| tr_fmt!("stat identity {0}", path.display().to_string()))?;
    if !meta.is_file() {
        bail!(tr_fmt!("identity path is not a file: {0}", path.display().to_string()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o640)).with_context(|| {
        tr_fmt!("chmod identity {0}", path.display().to_string())
    })?;
    #[cfg(target_os = "macos")]
    {
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(0)),
        )
        .with_context(|| tr_fmt!("chown identity {0}", path.display().to_string()))?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let uid = 0_u32;
        let gid = nix::unistd::User::from_name(service_user)
            .context(tr!("looking up service user"))?
            .map(|u| u.gid)
            .ok_or_else(|| anyhow::anyhow!(tr_fmt!("system user {0} not found", service_user)))?;
        nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(uid)), Some(gid)).with_context(
            || tr_fmt!("chown identity {0}", path.display().to_string()),
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_identity_for_service(_path: &Path, _service_user: &str) -> Result<()> {
    Ok(())
}

/// `link-p2p tun service install`
pub fn cmd_install(opts: InstallOpts, styler: &Styler) -> Result<()> {
    // Privilege check first — before any /etc or ProgramData writes (rc=USAGE).
    require_elevated()?;

    let exe = validate_service_binary(&std::env::current_exe().context(tr!("current_exe"))?)?;
    tun_daemon::resolve_up_role(Some(opts.role.as_str()), opts.to.as_deref())?;

    // Fail early if the chosen system identity parent cannot be created/written.
    crate::tun_ctl::verify_identity_parent_writable(&opts.identity)?;

    if let Some(parent) = opts.identity.parent() {
        fs::create_dir_all(parent).with_context(|| {
            tr_fmt!("creating {0}", parent.display().to_string())
        })?;
    }
    bootstrap_identity(
        &opts.identity,
        opts.identity_fallback.as_deref(),
        &opts.service_user,
    )?;
    secure_identity_for_service(&opts.identity, &opts.service_user)?;

    #[cfg(target_os = "linux")]
    {
        return cmd_install_linux(exe, opts, styler);
    }
    #[cfg(target_os = "macos")]
    {
        return cmd_install_macos(exe, opts, styler);
    }
    #[cfg(windows)]
    {
        return cmd_install_windows(exe, opts, styler);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (exe, opts, styler);
        unreachable!("require_elevated already rejected this platform");
    }
}

#[cfg(windows)]
fn cmd_install_windows(exe: PathBuf, opts: InstallOpts, styler: &Styler) -> Result<()> {
    // Ensure ProgramData runtime dir exists for tun.lock.
    let runtime = crate::tun_ctl::runtime_dir(crate::tun_ctl::RuntimeMode::System);
    fs::create_dir_all(&runtime).with_context(|| {
        tr_fmt!("creating {0}", runtime.display().to_string())
    })?;

    crate::win_service::install_scm(&exe, &opts)?;

    match crate::win_firewall::add_inbound_for_exe(&exe) {
        Ok(()) => {
            println!(
                "  {}",
                tr_fmt!(
                    "firewall: inbound allow for {0} (rule {1})",
                    exe.display().to_string(),
                    crate::win_firewall::RULE_NAME
                )
            );
        }
        Err(e) => {
            eprintln!(
                "  {}: {e:#}",
                styler.warn(&tr!(
                    "could not add Windows firewall rule automatically; allow inbound UDP for this executable manually if peers cannot reach you"
                ))
            );
        }
    }

    println!(
        "{}",
        styler.ok(&tr_fmt!(
            "installed and started {0} (control: link-p2p tun status --system)",
            crate::win_service::SERVICE_NAME
        ))
    );
    println!(
        "  {}",
        tr_fmt!(
            "identity: {0} (EndpointId is stable across service restarts)",
            opts.identity.display().to_string()
        )
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn cmd_install_linux(exe: PathBuf, opts: InstallOpts, styler: &Styler) -> Result<()> {
    ensure_system_user(&opts.service_user)?;

    let unit = render_unit(&exe, &opts)?;
    let path = unit_path();
    fs::write(&path, unit).with_context(|| {
        tr_fmt!("writing systemd unit {0}", path.display().to_string())
    })?;

    run_ok(Command::new("systemctl").arg("daemon-reload"), "systemctl daemon-reload")?;
    run_ok(
        Command::new("systemctl")
            .args(["enable", "--now", UNIT_NAME]),
        "systemctl enable --now",
    )?;

    println!(
        "{}",
        styler.ok(&tr_fmt!(
            "installed and started {0} (control: link-p2p tun status --system)",
            UNIT_NAME
        ))
    );
    println!(
        "  {}",
        tr_fmt!(
            "identity: {0} (EndpointId is stable across service restarts)",
            opts.identity.display().to_string()
        )
    );
    println!(
        "  {}",
        tr_fmt!(
            "logs: systemctl status {0}; journalctl -u {0} -f",
            UNIT_NAME
        )
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_install_macos(exe: PathBuf, opts: InstallOpts, styler: &Styler) -> Result<()> {
    fs::create_dir_all(MACOS_LOG_DIR).with_context(|| {
        tr_fmt!("creating {0}", MACOS_LOG_DIR)
    })?;

    let plist = render_plist(&exe, &opts)?;
    let path = plist_path();
    fs::write(&path, plist).with_context(|| {
        tr_fmt!("writing LaunchDaemon {0}", path.display().to_string())
    })?;

    // Big Sur+ uses bootstrap; ignore failure if an old load is still registered.
    let _ = Command::new("launchctl")
        .args(["bootout", "system", LAUNCHD_LABEL])
        .output();
    run_ok(
        Command::new("launchctl")
            .args(["bootstrap", "system", &path.to_string_lossy()]),
        "launchctl bootstrap",
    )?;
    run_ok(
        Command::new("launchctl")
            .args(["enable", &format!("system/{LAUNCHD_LABEL}")]),
        "launchctl enable",
    )?;

    println!(
        "{}",
        styler.ok(&tr_fmt!(
            "installed and started {0} (control: link-p2p tun status --system)",
            LAUNCHD_LABEL
        ))
    );
    println!(
        "  {}",
        tr_fmt!(
            "identity: {0} (EndpointId is stable across service restarts)",
            opts.identity.display().to_string()
        )
    );
    println!(
        "  {}",
        tr_fmt!(
            "logs: {0}/tun.log (configure newsyslog; see docs/subsystems/tun.md)",
            MACOS_LOG_DIR
        )
    );
    Ok(())
}

/// `link-p2p tun service uninstall`
pub fn cmd_uninstall(styler: &Styler) -> Result<()> {
    require_elevated()?;

    #[cfg(target_os = "linux")]
    {
        let path = unit_path();
        let _ = Command::new("systemctl")
            .args(["disable", "--now", UNIT_NAME])
            .output();
        if path.exists() {
            fs::remove_file(&path).with_context(|| {
                tr_fmt!("removing systemd unit {0}", path.display().to_string())
            })?;
        }
        run_ok(Command::new("systemctl").arg("daemon-reload"), "systemctl daemon-reload")?;
        println!(
            "{}",
            styler.ok(&tr_fmt!(
                "removed {0} (identity under /etc/link-p2p was kept)",
                UNIT_NAME
            ))
        );
    }

    #[cfg(target_os = "macos")]
    {
        let path = plist_path();
        let _ = Command::new("launchctl")
            .args(["bootout", "system", LAUNCHD_LABEL])
            .output();
        if path.exists() {
            fs::remove_file(&path).with_context(|| {
                tr_fmt!("removing LaunchDaemon {0}", path.display().to_string())
            })?;
        }
        println!(
            "{}",
            styler.ok(&tr_fmt!(
                "removed {0} (identity under /etc/link-p2p was kept)",
                LAUNCHD_LABEL
            ))
        );
    }

    #[cfg(windows)]
    {
        crate::win_service::uninstall_scm()?;
        if let Err(e) = crate::win_firewall::remove_inbound() {
            eprintln!(
                "  {}: {e:#}",
                styler.warn(&tr!("could not remove Windows firewall rule (may already be gone)"))
            );
        }
        println!(
            "{}",
            styler.ok(&tr_fmt!(
                "removed {0} (identity under ProgramData/link-p2p was kept)",
                crate::win_service::SERVICE_NAME
            ))
        );
    }

    Ok(())
}

/// Default identity path for `sudo link-p2p tun service install` (not root's).
#[cfg(unix)]
pub fn sudo_caller_identity_path() -> Option<PathBuf> {
    let user = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root")?;
    let mut path = nix::unistd::User::from_name(&user)
        .ok()
        .flatten()
        .map(|u| u.dir.join(".config").join("link-p2p").join("identity.key"));
    if path.is_none() {
        let mut fallback = PathBuf::from(if cfg!(target_os = "macos") {
            "/Users"
        } else {
            "/home"
        });
        fallback.push(&user);
        fallback.push(".config/link-p2p/identity.key");
        path = Some(fallback);
    }
    path.filter(|p| p.is_file())
}

#[cfg(windows)]
pub fn sudo_caller_identity_path() -> Option<PathBuf> {
    // Elevated install: prefer the installing user's LocalAppData key.
    let local = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty())?;
    let p = PathBuf::from(local).join("link-p2p").join("identity.key");
    p.is_file().then_some(p)
}

#[cfg(not(any(unix, windows)))]
pub fn sudo_caller_identity_path() -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_hub_unit_contains_required_directives() {
        let unit = render_unit(
            Path::new("/usr/local/bin/link-p2p"),
            &InstallOpts {
                role: "hub".into(),
                to: None,
                identity: PathBuf::from("/etc/link-p2p/identity.key"),
                service_user: "link-p2p".into(),
                identity_fallback: None,
            },
        )
        .unwrap();
        assert!(unit.contains("RuntimeDirectory=link-p2p"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN"));
        assert!(unit.contains("--foreground --system"));
        assert!(unit.contains("--identity /etc/link-p2p/identity.key"));
        assert!(!unit.contains("--to "));
    }

    #[test]
    fn render_spoke_unit_includes_to() {
        let unit = render_unit(
            Path::new("/usr/bin/link-p2p"),
            &InstallOpts {
                role: "spoke".into(),
                to: Some("abc123".into()),
                identity: PathBuf::from("/etc/link-p2p/id.key"),
                service_user: "link-p2p".into(),
                identity_fallback: None,
            },
        )
        .unwrap();
        assert!(unit.contains("--role spoke"));
        assert!(unit.contains("--to abc123"));
    }

    #[test]
    fn rejects_home_binary() {
        let err = check_service_binary_path(Path::new("/home/alice/bin/link-p2p")).unwrap_err();
        assert_eq!(exit::code_from(&err), exit::USAGE);
    }

    #[test]
    fn rejects_cargo_target_binary() {
        let err = check_service_binary_path(Path::new(
            "/home/kangxi/Projects/link-p2p/target/debug/link-p2p",
        ))
        .unwrap_err();
        assert_eq!(exit::code_from(&err), exit::USAGE);
    }

    #[test]
    fn render_hub_plist_contains_required_keys() {
        let plist = render_plist(
            Path::new("/usr/local/bin/link-p2p"),
            &InstallOpts {
                role: "hub".into(),
                to: None,
                identity: PathBuf::from("/etc/link-p2p/identity.key"),
                service_user: "link-p2p".into(),
                identity_fallback: None,
            },
        )
        .unwrap();
        assert!(plist.contains("<string>com.link-p2p.tun</string>"));
        assert_eq!(PLIST_NAME, "com.link-p2p.tun.plist");
        assert!(plist.contains("--foreground</string>"));
        assert!(plist.contains("--system</string>"));
        assert!(plist.contains("/var/log/link-p2p/tun.log</string>"));
    }

    #[test]
    fn render_spoke_plist_includes_to() {
        let plist = render_plist(
            Path::new("/usr/local/bin/link-p2p"),
            &InstallOpts {
                role: "spoke".into(),
                to: Some("abc123".into()),
                identity: PathBuf::from("/etc/link-p2p/id.key"),
                service_user: "link-p2p".into(),
                identity_fallback: None,
            },
        )
        .unwrap();
        assert!(plist.contains("<string>spoke</string>"));
        assert!(plist.contains("<string>abc123</string>"));
    }
}
