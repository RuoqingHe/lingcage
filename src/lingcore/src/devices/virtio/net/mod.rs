// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio network device, section 5.1 of virtio 1.2.
//!
//! The device carries Ethernet frames between the guest and a host
//! stream. Address, host stack and its reach are decided by the program
//! assembling the machine.

pub mod carrier;
pub mod device;
pub mod frame;
pub mod pcap;
// Host sockets of the stack are opened through libc on Linux.
#[cfg(all(feature = "netstack", target_os = "linux"))]
pub mod stack;
