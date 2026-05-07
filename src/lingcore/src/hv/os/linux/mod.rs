// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Mechanisms built on `eventfd(2)` and a KVM ioctl, plus a `poll(2)`
//! wait over several of them.

pub mod ioeventfd;
pub mod irqfd;
pub mod waiting;
