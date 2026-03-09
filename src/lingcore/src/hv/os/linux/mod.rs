// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Mechanisms built on `eventfd(2)` and a KVM ioctl.

pub mod ioeventfd;
pub mod irqfd;
