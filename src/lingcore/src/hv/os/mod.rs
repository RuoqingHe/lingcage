// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Mechanisms specific to one host operating system.

#[cfg(target_os = "linux")]
pub mod linux;
