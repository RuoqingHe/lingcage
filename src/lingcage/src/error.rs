// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Error type of the crate, which is matchable and attributable so that
//! a control plane could distinguish different failure outcomes.

use thiserror::Error;

/// Errors thrown by LingCage.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to perform host IO operation.
    #[error("host IO operation failed")]
    Io(#[source] std::io::Error),
    /// Image contains files not allowed in a template.
    #[error("image contains files not allowed in template: {found:?}")]
    Sanitize {
        /// Paths found which are not allowed in a template.
        found: Vec<String>,
    },
}

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, Error>;
