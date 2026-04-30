// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio socket device, section 5.10 of virtio 1.2.
//!
//! The device carries bytes between a guest socket and a host socket.
//! Protocol on those bytes is decided by the program assembling the
//! machine.

pub mod connection;
pub mod host;
pub mod packet;
