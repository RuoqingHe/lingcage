// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Sandbox in this process, a guest cloned from template and driven
//! through its control connection, with its console attached.

pub mod console;
pub mod demux;

use std::io::Read as _;

use crate::error::{Error, Result};

/// Identity of the guest, applied at handshake.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Vsock context id of the guest.
    pub cid: u64,
    /// Hostname to be set in the guest.
    pub hostname: String,
    /// Value written to `/etc/machine-id` inside the guest.
    pub machine_id: String,
}

/// Fill `bytes` with random data read from `/dev/urandom`.
pub(crate) fn draw(bytes: &mut [u8]) -> Result<()> {
    let mut source = std::fs::File::open("/dev/urandom").map_err(Error::Io)?;
    source.read_exact(bytes).map_err(Error::Io)
}
