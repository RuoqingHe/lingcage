// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! A single guest and the parts a backend builds for it.

use crate::hv::irq::{IrqSender, MsiSender};
use crate::hv::memory::VmMemory;
#[cfg(target_os = "linux")]
use crate::hv::os::linux::ioeventfd::IoeventFdRegistry;
use crate::hv::vcpu::Vcpu;
use crate::hv::{Cap, Result};

/// One guest. Each backend names its concrete part types, so code
/// written against `Vm` builds with one backend. It is shared by
/// threads, so `Send` and `Sync`.
pub trait Vm: Send + Sync {
    /// vCPU type of the backend.
    type Vcpu: Vcpu;
    /// Guest memory type of the backend.
    type Memory: VmMemory;
    /// Legacy line sender of the backend.
    type IrqSender: IrqSender;
    /// MSI sender of the backend.
    type MsiSender: MsiSender;
    /// Ioeventfd registry of the backend.
    #[cfg(target_os = "linux")]
    type IoeventFdRegistry: IoeventFdRegistry;

    /// Create the vCPU numbered `cpu_index`.
    fn create_vcpu(&self, cpu_index: u16) -> Result<Self::Vcpu>;

    /// Create the guest physical address space.
    fn create_vm_memory(&self) -> Result<Self::Memory>;

    /// Create a sender for legacy line `pin`.
    fn create_irq_sender(&self, pin: u8) -> Result<Self::IrqSender>;

    /// Create an MSI sender.
    fn create_msi_sender(&self) -> Result<Self::MsiSender>;

    /// Create a registry of kernel-side ioeventfds.
    #[cfg(target_os = "linux")]
    fn create_ioeventfd_registry(&self) -> Result<Self::IoeventFdRegistry>;

    /// Returns whether the backend has `cap`.
    fn capability(&self, cap: Cap) -> bool;
}
