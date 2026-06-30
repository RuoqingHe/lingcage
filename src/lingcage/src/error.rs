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
    /// Failed calling into `lingcore`.
    #[error("`lingcore` call failed")]
    Lingcore(#[source] lingcore::machine::Error),
    /// Error occurred in guest protocol.
    #[error("guest protocol failed")]
    Protocol(#[source] crate::lcp::Error),
    /// No template registered with given id.
    #[error("no template named {id}")]
    TemplateMissing {
        /// Template id looked up.
        id: String,
    },
    /// Template failed verification at registration time, with the reason
    /// attached.
    #[error("template failed verification at registration time: {what}")]
    TemplateBad {
        /// Reason of the failure, together with suggested action.
        what: String,
    },
    /// Template is still in use by a live sandbox.
    #[error("template is in use")]
    TemplateInUse {
        /// Id of the template requested for removal.
        id: String,
    },
    /// Image contains files not allowed in a template.
    #[error("image contains files not allowed in template: {found:?}")]
    Sanitize {
        /// Paths found which are not allowed in a template.
        found: Vec<String>,
    },
    /// Requested feature is not implemented in this build.
    #[error("feature not implemented in this build: {0}")]
    Unsupported(&'static str),
    /// Error reported by agent, or a frame received out of sequence.
    #[error("error reported by agent, or frame out of sequence: {what}")]
    Agent {
        /// Report sent by agent.
        what: String,
    },
    /// Operation did not finish before deadline.
    #[error("operation did not finish before deadline: {0}")]
    Timeout(&'static str),
    /// Guest did not become ready in time, console tail attached.
    #[error("guest not ready in time, console tail: {console_tail}")]
    NotReady {
        /// Last bytes of guest console output.
        console_tail: String,
        /// Handshake error which caused the failure.
        #[source]
        source: Box<Error>,
    },
    /// Requested limits do not match the shape of the template.
    #[error("limits {asked} do not match template shape {shape}")]
    Shape {
        /// Limits specified in the spec.
        asked: String,
        /// Shape used when the template was baked.
        shape: String,
    },
}

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, Error>;
