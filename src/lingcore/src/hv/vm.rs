// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! A single guest and the parts a backend builds for it.

use std::thread::JoinHandle;

use crate::hv::irq::{IrqSender, MsiSender};
use crate::hv::memory::VmMemory;
#[cfg(target_os = "linux")]
use crate::hv::os::linux::ioeventfd::IoeventFdRegistry;
use crate::hv::vcpu::Vcpu;
use crate::hv::{Cap, Error, Result, StateBlob};

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

    /// Create the in-kernel irqchip. Kernel then handles guest idle, and
    /// `VmExit::Halt` changes meaning accordingly, so the machine calls this
    /// during setup. Default returns `Unsupported`.
    fn enable_irqchip(&self) -> Result<()> {
        Err(Error::Unsupported("enable_irqchip"))
    }

    /// Capture the in-kernel irqchip state, PIC, IOAPIC and PIT on x86_64,
    /// GIC on aarch64, AIA on riscv64. Default returns `Unsupported`.
    fn get_irqchip_state(&self) -> Result<StateBlob> {
        Err(Error::Unsupported("get_irqchip_state"))
    }

    /// Restore a blob captured by `get_irqchip_state` on the same backend
    /// and architecture. Default returns `Unsupported`.
    fn set_irqchip_state(&self, _state: &StateBlob) -> Result<()> {
        Err(Error::Unsupported("set_irqchip_state"))
    }

    /// Capture the guest clock together with the host instant it was read
    /// at. Default returns `Unsupported`.
    fn get_clock(&self) -> Result<StateBlob> {
        Err(Error::Unsupported("get_clock"))
    }

    /// Restore the clock as captured by `get_clock`, for replaying a
    /// recorded run. Default returns `Unsupported`.
    fn set_clock(&self, _state: &StateBlob) -> Result<()> {
        Err(Error::Unsupported("set_clock"))
    }

    /// Restore the captured clock advanced by the host time elapsed since
    /// capture, for a clone which resumes on current wall clock time. Guest
    /// sees one forward jump. Default returns `Unsupported`.
    fn set_clock_elapsed(&self, _state: &StateBlob) -> Result<()> {
        Err(Error::Unsupported("set_clock_elapsed"))
    }

    /// Kick the vCPU numbered `cpu_index` out of `run`. `handle` is the
    /// thread blocked in the backend running it. Interrupted run returns
    /// `VmExit::Interrupted`.
    fn stop_vcpu<T>(&self, cpu_index: u16, handle: &JoinHandle<T>) -> Result<()>;
}
