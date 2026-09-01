//! Non-Unix/non-Windows: daemon worker/spawn unsupported.

use super::*;
use anyhow::{bail, Result};

pub(crate) async fn run_skeleton_control(
    _listener: (),
    _role: &str,
    _session: &str,
) -> Result<()> {
    bail!(tr!("TUN daemon worker is Unix-only in this build"))
}

pub(crate) async fn run_live_control_and_data(
    _listener: (),
    _role: &str,
    _session: &str,
    _mode: RuntimeMode,
    _data_plane: DataPlaneSource,
) -> Result<()> {
    bail!(tr!("TUN daemon worker is Unix-only in this build"))
}
