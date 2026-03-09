// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Opened hypervisor handle.

use crate::hv::Result;
use crate::hv::vm::Vm;

/// Opened hypervisor, `/dev/kvm` for example, opened once per process.
pub trait Hypervisor {
    /// VM type of the backend.
    type Vm: Vm;

    /// Create a VM without vCPU, memory or device yet.
    fn create_vm(&self) -> Result<Self::Vm>;
}
