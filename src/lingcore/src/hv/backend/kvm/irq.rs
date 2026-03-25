// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Interrupt injection, legacy lines, MSIs and the GSI routing table.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KvmIrqRouting, kvm_irq_routing_entry,
    kvm_irq_routing_irqchip, kvm_irq_routing_msi, kvm_msi,
};
use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::hv::backend::kvm::kvm_err;
use crate::hv::irq::{IrqSender, MsiSender};
use crate::hv::os::linux::irqfd::IrqFd;
use crate::hv::{Error, Result};

/// Legacy interrupt line, the eventfd bound to its pin by `KVM_IRQFD`.
/// `send` writes the fd and issues no ioctl on the VM fd. Binding is
/// not undone on drop, it ends together with the VM fd.
pub struct KvmIrqSender {
    eventfd: EventFd,
}

impl KvmIrqSender {
    /// Wrap `eventfd`, which is already bound to its pin through `KVM_IRQFD`.
    pub(in crate::hv::backend::kvm) fn new(eventfd: EventFd) -> Self {
        KvmIrqSender { eventfd }
    }
}

impl IrqSender for KvmIrqSender {
    fn send(&self) -> Result<()> {
        // Without resamplefd, KVM raises the line and lowers it for each write.
        self.eventfd.write(1).map_err(kvm_err("irqfd write"))
    }
}

/// irqchip which a legacy pin routes to. IOAPIC on x86_64, irqchip 0 on
/// other architectures.
#[cfg(target_arch = "x86_64")]
const PIN_IRQCHIP: u32 = kvm_bindings::KVM_IRQCHIP_IOAPIC;
#[cfg(not(target_arch = "x86_64"))]
const PIN_IRQCHIP: u32 = 0;

/// First GSI taken by an irqfd. Legacy pins are `u8` and stay below it.
const FIRST_MSI_GSI: u32 = 256;

/// MSI route of one irqfd.
#[derive(Clone, Copy)]
struct MsiRoute {
    addr: u64,
    data: u32,
    masked: bool,
}

impl Default for MsiRoute {
    /// Masked, so that the route stays out of the table until address and
    /// data are set.
    fn default() -> Self {
        MsiRoute {
            addr: 0,
            data: 0,
            masked: true,
        }
    }
}

/// Routing table of the guest. `KVM_SET_GSI_ROUTING` overwrites the
/// table, so legacy pins which have a sender are kept here and written
/// together with MSI routes.
#[derive(Default)]
pub(in crate::hv::backend::kvm) struct Routing {
    pub(in crate::hv::backend::kvm) pins: BTreeSet<u8>,
    msi: BTreeMap<u32, MsiRoute>,
    next_gsi: u32,
}

impl Routing {
    /// Returns GSI of the next irqfd.
    fn take_gsi(&mut self) -> u32 {
        let gsi = FIRST_MSI_GSI + self.next_gsi;
        self.next_gsi += 1;
        gsi
    }

    /// Write the table through `KVM_SET_GSI_ROUTING`. Masked routes are
    /// left out.
    pub(in crate::hv::backend::kvm) fn apply(&self, vm: &VmFd) -> Result<()> {
        let mut entries = Vec::with_capacity(self.pins.len() + self.msi.len());
        for &pin in &self.pins {
            let mut entry = kvm_irq_routing_entry {
                gsi: u32::from(pin),
                type_: KVM_IRQ_ROUTING_IRQCHIP,
                ..Default::default()
            };
            entry.u.irqchip = kvm_irq_routing_irqchip {
                irqchip: PIN_IRQCHIP,
                pin: u32::from(pin),
            };
            entries.push(entry);
        }
        for (&gsi, route) in &self.msi {
            if route.masked {
                continue;
            }
            let mut entry = kvm_irq_routing_entry {
                gsi,
                type_: KVM_IRQ_ROUTING_MSI,
                ..Default::default()
            };
            entry.u.msi = kvm_irq_routing_msi {
                address_lo: route.addr as u32,
                address_hi: (route.addr >> 32) as u32,
                data: route.data,
                ..Default::default()
            };
            entries.push(entry);
        }
        let table = KvmIrqRouting::from_entries(&entries)
            .map_err(|_| Error::Other("guest holds more routes than KVM accepts"))?;
        vm.set_gsi_routing(&table)
            .map_err(kvm_err("KVM_SET_GSI_ROUTING"))
    }
}

/// Sender for message signalled interrupts. Address and data are passed
/// with each `send`, so all devices of a guest share one sender.
pub struct KvmMsiSender {
    vm: Arc<VmFd>,
    routing: Arc<Mutex<Routing>>,
}

impl KvmMsiSender {
    pub(in crate::hv::backend::kvm) fn new(vm: Arc<VmFd>, routing: Arc<Mutex<Routing>>) -> Self {
        KvmMsiSender { vm, routing }
    }
}

impl MsiSender for KvmMsiSender {
    type IrqFd = KvmIrqFd;

    fn send(&self, addr: u64, data: u32) -> Result<()> {
        let msi = kvm_msi {
            address_lo: addr as u32,
            address_hi: (addr >> 32) as u32,
            data,
            ..Default::default()
        };
        self.vm.signal_msi(msi).map_err(kvm_err("KVM_SIGNAL_MSI"))?;
        Ok(())
    }

    fn create_irqfd(&self) -> Result<KvmIrqFd> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        let gsi = {
            let mut routing = self.routing.lock().unwrap();
            let gsi = routing.take_gsi();
            // Masked, so the route is out of the table and the fd is off the
            // GSI until the caller sets address and data and unmasks it.
            routing.msi.insert(gsi, MsiRoute::default());
            gsi
        };
        Ok(KvmIrqFd {
            vm: Arc::clone(&self.vm),
            routing: Arc::clone(&self.routing),
            eventfd,
            gsi,
        })
    }
}

/// eventfd bound to a GSI through `KVM_IRQFD`, together with the MSI
/// route of that GSI. Writing the fd injects the MSI in kernel.
pub struct KvmIrqFd {
    vm: Arc<VmFd>,
    routing: Arc<Mutex<Routing>>,
    eventfd: EventFd,
    gsi: u32,
}

impl KvmIrqFd {
    /// Apply `change` to the route and rewrite the table.
    fn update(&self, change: impl FnOnce(&mut MsiRoute)) -> Result<()> {
        let mut routing = self.routing.lock().unwrap();
        let route = routing
            .msi
            .get_mut(&self.gsi)
            .ok_or(Error::Other("irqfd has no route"))?;
        change(route);
        routing.apply(&self.vm)
    }
}

impl AsFd for KvmIrqFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: `eventfd` is owned by `self`, so the fd stays open during
        // the lifetime of the borrow.
        unsafe { BorrowedFd::borrow_raw(self.eventfd.as_raw_fd()) }
    }
}

impl IrqFd for KvmIrqFd {
    fn set_addr(&self, addr: u64) -> Result<()> {
        self.update(|route| route.addr = addr)
    }

    fn set_data(&self, data: u32) -> Result<()> {
        self.update(|route| route.data = data)
    }

    /// Masking unregisters the irqfd before the route leaves the table,
    /// unmasking registers it after the route is in. Note that an irqfd on
    /// a GSI without route panicked SVM hosts before kernel commit
    /// a80ced6ea514.
    fn set_masked(&self, masked: bool) -> Result<()> {
        let mut routing = self.routing.lock().unwrap();
        let route = routing
            .msi
            .get_mut(&self.gsi)
            .ok_or(Error::Other("irqfd has no route"))?;
        if route.masked == masked {
            return Ok(());
        }
        route.masked = masked;
        if masked {
            self.vm
                .unregister_irqfd(&self.eventfd, self.gsi)
                .map_err(kvm_err("KVM_IRQFD"))?;
            routing.apply(&self.vm)
        } else {
            routing.apply(&self.vm)?;
            self.vm
                .register_irqfd(&self.eventfd, self.gsi)
                .map_err(kvm_err("KVM_IRQFD"))
        }
    }
}

impl Drop for KvmIrqFd {
    fn drop(&mut self) {
        // KVM detaches the irqfd on eventfd hangup. The route stays in the
        // table held by KVM until next write, with no fd on its GSI.
        self.routing.lock().unwrap().msi.remove(&self.gsi);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::backend::kvm::irq::*;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::backend::kvm::vm::KvmVm;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::vm::Vm;

    /// Returns whether `fd` is registered on its GSI. A second `KVM_IRQFD`
    /// assign of a registered eventfd fails with `EBUSY`. Probe which
    /// succeeds is undone afterwards.
    #[cfg(target_arch = "x86_64")]
    fn assigned(vm: &KvmVm, fd: &KvmIrqFd) -> bool {
        match vm.fd.register_irqfd(&fd.eventfd, fd.gsi) {
            Ok(()) => {
                vm.fd
                    .unregister_irqfd(&fd.eventfd, fd.gsi)
                    .expect("undo the probe");
                false
            }
            Err(err) => {
                assert_eq!(err.errno(), 16, "expected EBUSY");
                true
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_irqfd_routing() {
        // GSI assignment, masking and route removal of irqfds.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");

        // Legacy line. Its pin is in each table written after this.
        let com1 = vm.create_irq_sender(4).expect("sender on IRQ 4");
        assert!(vm.routing.lock().unwrap().pins.contains(&4));

        let msi = vm.create_msi_sender().expect("msi sender");
        let one = msi.create_irqfd().expect("irqfd");
        let two = msi.create_irqfd().expect("second irqfd");
        assert_ne!(one.gsi, two.gsi, "two irqfds got the same GSI");
        assert!(one.gsi >= FIRST_MSI_GSI, "irqfd took a legacy pin number");

        // Both routes are still masked, so neither of them is in the table.
        let fresh = vm.routing.lock().unwrap();
        assert!(
            fresh.msi[&one.gsi].masked,
            "route without message went to KVM"
        );
        assert!(
            fresh.msi[&two.gsi].masked,
            "route without message went to KVM"
        );
        drop(fresh);
        // Masked irqfd is not registered on its GSI.
        assert!(!assigned(&vm, &one), "unprogrammed irqfd holds its GSI");

        // Each call rewrites the table with the legacy pin and both MSI
        // routes. `KVM_SET_GSI_ROUTING` fails on a table it can not route.
        one.set_addr(0xfee0_0000).expect("address");
        one.set_data(0x31).expect("data");
        one.set_masked(false).expect("unmask");
        two.set_addr(0xfee0_0000).expect("address");
        two.set_data(0x32).expect("data");
        two.set_masked(false).expect("unmask");
        assert!(assigned(&vm, &one), "unmasked irqfd is off its GSI");

        // Masking unregisters the fd, repeating it is a no-op, and unmasking
        // registers it again.
        one.set_masked(true).expect("mask");
        assert!(!assigned(&vm, &one), "masked irqfd holds its GSI");
        one.set_masked(true).expect("mask twice");
        one.set_masked(false).expect("unmask again");
        assert!(assigned(&vm, &one), "unmasked irqfd is off its GSI");

        let routing = vm.routing.lock().unwrap();
        assert!(routing.pins.contains(&4), "legacy pin left the table");
        assert_eq!(routing.msi.len(), 2);
        drop(routing);

        one.eventfd.write(1).expect("fire the irqfd");
        com1.send().expect("pulse IRQ 4");

        let gone = two.gsi;
        drop(two);
        assert!(
            !vm.routing.lock().unwrap().msi.contains_key(&gone),
            "dropped irqfd left its route behind"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_send_msi() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");
        let msi = vm.create_msi_sender().expect("msi sender");

        // Without vCPU there is no LAPIC to deliver to. `KVM_SIGNAL_MSI`
        // returns -1, which shows as `EPERM` at the syscall boundary.
        assert!(
            msi.send(0xfee0_0000, 0x30).is_err(),
            "message delivered with no LAPIC to take it"
        );

        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        // Vector 0x30, fixed delivery, addressed to APIC id 0.
        msi.send(0xfee0_0000, 0x30).expect("deliver to vcpu 0");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_legacy_irq_line() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        // `KVM_IRQFD` fails with `EINVAL` before `KVM_CREATE_IRQCHIP`.
        assert!(
            vm.create_irq_sender(4).is_err(),
            "pin bound with no controller behind it"
        );

        vm.enable_irqchip().expect("in-kernel irqchip");
        let com1 = vm.create_irq_sender(4).expect("sender on IRQ 4");
        com1.send().expect("pulse");
        com1.send().expect("pulse again");
    }
}
