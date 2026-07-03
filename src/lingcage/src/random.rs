// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Random bytes drawn for the identity of a sandbox or a build.

use crate::error::{Error, Result};

/// Fill `bytes` from kernel random pool. A spawn draws three times, and
/// `getrandom` costs only one syscall while reading from `/dev/urandom`
/// needs open, read and close.
pub(crate) fn draw(bytes: &mut [u8]) -> Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        // SAFETY: pointer and length describe the unfilled tail of `bytes`.
        let drawn = unsafe {
            libc::getrandom(
                bytes[at..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - at,
                0,
            )
        };
        if drawn < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Io(err));
        }
        at += drawn as usize;
    }
    Ok(())
}
