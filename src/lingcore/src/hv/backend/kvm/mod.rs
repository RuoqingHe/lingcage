// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    KVM_API_VERSION, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_MEM_LOG_DIRTY_PAGES,
    KVM_MEM_READONLY, KvmIrqRouting, kvm_irq_routing_entry, kvm_irq_routing_irqchip,
    kvm_irq_routing_msi, kvm_msi, kvm_userspace_memory_region,
};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Cap, IoEventAddress, Kvm, NoDatamatch, VcpuFd, VmFd};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::hv::irq::{IrqSender, MsiSender};
use crate::hv::memory::{MemMapOption, VmMemory};
use crate::hv::os::linux::ioeventfd::{IoeventFd, IoeventFdRegistry};
use crate::hv::os::linux::irqfd::IrqFd;
use crate::hv::{Error, Result};

/// Map a `kvm_ioctls::Error`, or the `io::Error` of an eventfd call, to
/// `Error::Os` with operation `op`.
fn kvm_err<E: Into<kvm_ioctls::Error>>(op: &'static str) -> impl Fn(E) -> Error {
    move |err| Error::Os {
        op,
        errno: err.into().errno(),
    }
}

/// Opened `/dev/kvm` handle.
pub struct KvmHv {
    kvm: Kvm,
}

impl KvmHv {
    /// Open `/dev/kvm`, refuse a kernel whose `KVM_GET_API_VERSION` is not
    /// `KVM_API_VERSION`.
    pub fn new() -> Result<Self> {
        let kvm = Kvm::new().map_err(kvm_err("open /dev/kvm"))?;
        // `get_api_version` returns the raw ioctl result, negative value
        // means failure with errno set.
        let version = kvm.get_api_version();
        if version < 0 {
            return Err(Error::Os {
                op: "KVM_GET_API_VERSION",
                errno: kvm_ioctls::Error::last().errno(),
            });
        }
        if version != KVM_API_VERSION as i32 {
            return Err(Error::ApiVersion(version));
        }
        Ok(KvmHv { kvm })
    }

    /// Create a guest through `KVM_CREATE_VM`, without vCPU or memory.
    pub fn create_vm(&self) -> Result<KvmVm> {
        let fd = self.kvm.create_vm().map_err(kvm_err("KVM_CREATE_VM"))?;
        Ok(KvmVm {
            fd: Arc::new(fd),
            routing: Arc::new(Mutex::new(Routing::default())),
        })
    }
}

/// Guest handle, the VM fd returned by `KVM_CREATE_VM`. Parts created
/// from it share the fd.
pub struct KvmVm {
    fd: Arc<VmFd>,
    routing: Arc<Mutex<Routing>>,
}

impl KvmVm {
    /// Create the guest physical address space, no region mapped yet.
    pub fn create_vm_memory(&self) -> Result<KvmMemory> {
        Ok(KvmMemory {
            vm: Arc::clone(&self.fd),
            next_slot: AtomicU32::new(0),
            slots: Mutex::new(HashMap::new()),
        })
    }

    /// Create the in-kernel irqchip (PIC, IOAPIC and LAPICs) through
    /// `KVM_CREATE_IRQCHIP`, and the i8254 PIT through `KVM_CREATE_PIT2`.
    #[cfg(target_arch = "x86_64")]
    pub fn enable_irqchip(&self) -> Result<()> {
        self.fd
            .create_irq_chip()
            .map_err(kvm_err("KVM_CREATE_IRQCHIP"))?;
        // `KVM_PIT_SPEAKER_DUMMY` registers a speaker stub at port 0x61 in
        // kernel, so guest write there does not exit to VMM.
        self.fd
            .create_pit2(kvm_pit_config {
                flags: KVM_PIT_SPEAKER_DUMMY,
                ..Default::default()
            })
            .map_err(kvm_err("KVM_CREATE_PIT2"))?;
        Ok(())
    }

    /// Create the vCPU with id `cpu_index` through `KVM_CREATE_VCPU`. A
    /// second vCPU with the same id fails with `EEXIST`.
    pub fn create_vcpu(&self, cpu_index: u16) -> Result<KvmVcpu> {
        let fd = self
            .fd
            .create_vcpu(u64::from(cpu_index))
            .map_err(kvm_err("KVM_CREATE_VCPU"))?;
        Ok(KvmVcpu { fd })
    }

    /// Bind a new eventfd to irqchip pin `pin` through `KVM_IRQFD` and
    /// return the sender which writes it. Pin is fixed for each sender.
    pub fn create_irq_sender(&self, pin: u8) -> Result<KvmIrqSender> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        {
            let mut routing = self.routing.lock().unwrap();
            routing.pins.insert(pin);
            routing.apply(&self.fd)?;
        }
        self.fd
            .register_irqfd(&eventfd, u32::from(pin))
            .map_err(kvm_err("KVM_IRQFD"))?;
        Ok(KvmIrqSender { eventfd })
    }

    /// Create the MSI sender. Returns `Unsupported` without
    /// `KVM_CAP_SIGNAL_MSI`.
    pub fn create_msi_sender(&self) -> Result<KvmMsiSender> {
        if !self.fd.check_extension(Cap::SignalMsi) {
            return Err(Error::Unsupported("KVM_CAP_SIGNAL_MSI"));
        }
        Ok(KvmMsiSender {
            vm: Arc::clone(&self.fd),
            routing: Arc::clone(&self.routing),
        })
    }

    /// Create the ioeventfd registry.
    pub fn create_ioeventfd_registry(&self) -> KvmIoeventFdRegistry {
        KvmIoeventFdRegistry {
            vm: Arc::clone(&self.fd),
        }
    }
}

/// Guest physical address space of one guest, as KVM memory slots.
/// `slots` maps each mapped guest address to the slot number given to
/// it, since `KVM_SET_USER_MEMORY_REGION` addresses a region by slot.
pub struct KvmMemory {
    vm: Arc<VmFd>,
    next_slot: AtomicU32,
    slots: Mutex<HashMap<u64, u32>>,
}

impl VmMemory for KvmMemory {
    fn mem_map(&self, gpa: u64, size: u64, hva: usize, opt: MemMapOption) -> Result<()> {
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst);
        let mut flags = 0u32;
        if opt.log_dirty {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }
        if !opt.write {
            flags |= KVM_MEM_READONLY;
        }
        let region = kvm_userspace_memory_region {
            slot,
            flags,
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: hva as u64,
        };
        // SAFETY: `hva` points to `size` bytes of host memory which stay
        // mapped as long as the region exists.
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .map_err(kvm_err("KVM_SET_USER_MEMORY_REGION"))?
        };
        self.slots.lock().unwrap().insert(gpa, slot);
        Ok(())
    }

    fn unmap(&self, gpa: u64, _size: u64) -> Result<()> {
        let slot = self
            .slots
            .lock()
            .unwrap()
            .remove(&gpa)
            .ok_or(Error::Other("unmap: no region at given guest address"))?;
        let region = kvm_userspace_memory_region {
            slot,
            flags: 0,
            guest_phys_addr: gpa,
            memory_size: 0,
            userspace_addr: 0,
        };
        // SAFETY: zero `memory_size` deletes the slot, no host address is read.
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .map_err(kvm_err("KVM_SET_USER_MEMORY_REGION"))?
        };
        Ok(())
    }
}

/// vCPU handle, the fd returned by `KVM_CREATE_VCPU`.
pub struct KvmVcpu {
    // TODO: drop the attribute once running the vCPU reads this fd.
    #[cfg_attr(not(test), expect(dead_code, reason = "only the test reads the fd"))]
    fd: VcpuFd,
}

/// Legacy interrupt line, the eventfd bound to its pin by `KVM_IRQFD`.
/// `send` writes the fd and issues no ioctl on the VM fd. Binding is
/// not undone on drop, it ends together with the VM fd.
pub struct KvmIrqSender {
    eventfd: EventFd,
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
struct Routing {
    pins: BTreeSet<u8>,
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
    fn apply(&self, vm: &VmFd) -> Result<()> {
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

/// Datamatch of an ioeventfd, at the width KVM compares it in.
/// `kvm-ioctls` takes `len` from the type. `Any` means `len` 0, a write
/// of any width.
enum Datamatch {
    Any,
    Byte(u8),
    Word(u16),
    Long(u32),
    Quad(u64),
}

impl Datamatch {
    /// Build the datamatch for `len` and `data`. `len` is not used without
    /// `data`.
    fn new(len: u8, data: Option<u64>) -> Result<Self> {
        match (data, len) {
            (None, _) => Ok(Datamatch::Any),
            (Some(d), 1) => Ok(Datamatch::Byte(d as u8)),
            (Some(d), 2) => Ok(Datamatch::Word(d as u16)),
            (Some(d), 4) => Ok(Datamatch::Long(d as u32)),
            (Some(d), 8) => Ok(Datamatch::Quad(d)),
            (Some(_), _) => Err(Error::Other("datamatch should be 1, 2, 4 or 8 bytes wide")),
        }
    }
}

/// Ioeventfd, the eventfd signalled by KVM on a guest write, together
/// with its binding. Deassign needs address, width and value of the
/// assign, so `bound` is kept until `deregister`.
pub struct KvmIoeventFd {
    eventfd: EventFd,
    bound: Mutex<Option<(u64, Datamatch)>>,
}

impl IoeventFd for KvmIoeventFd {}

/// Ioeventfd registry, which issues `KVM_IOEVENTFD` on the VM fd.
pub struct KvmIoeventFdRegistry {
    vm: Arc<VmFd>,
}

impl IoeventFdRegistry for KvmIoeventFdRegistry {
    type IoeventFd = KvmIoeventFd;

    fn create(&self) -> Result<KvmIoeventFd> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        Ok(KvmIoeventFd {
            eventfd,
            bound: Mutex::new(None),
        })
    }

    fn register(&self, fd: &KvmIoeventFd, gpa: u64, len: u8, data: Option<u64>) -> Result<()> {
        let datamatch = Datamatch::new(len, data)?;
        let addr = IoEventAddress::Mmio(gpa);
        match datamatch {
            Datamatch::Any => self.vm.register_ioevent(&fd.eventfd, &addr, NoDatamatch),
            Datamatch::Byte(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Word(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Long(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Quad(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
        }
        .map_err(kvm_err("KVM_IOEVENTFD"))?;
        *fd.bound.lock().unwrap() = Some((gpa, datamatch));
        Ok(())
    }

    fn deregister(&self, fd: &KvmIoeventFd) -> Result<()> {
        let (gpa, datamatch) = fd
            .bound
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::Other("ioeventfd is not bound"))?;
        let addr = IoEventAddress::Mmio(gpa);
        match datamatch {
            Datamatch::Any => self.vm.unregister_ioevent(&fd.eventfd, &addr, NoDatamatch),
            Datamatch::Byte(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Word(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Long(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Quad(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
        }
        .map_err(kvm_err("KVM_IOEVENTFD"))
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::os::fd::AsRawFd;

    use crate::hv::backend::kvm::*;

    const PAGE: usize = 4096;

    #[test]
    fn test_open_kvm() {
        KvmHv::new().expect("/dev/kvm at the expected KVM API version");
    }

    #[test]
    fn test_create_guests() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let one = hv.create_vm().expect("first guest");
        let two = hv.create_vm().expect("second guest");
        assert_ne!(one.fd.as_raw_fd(), two.fd.as_raw_fd());
    }

    #[test]
    fn test_map_unmap_guest_memory() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");

        let size = 2 * PAGE;
        let layout = Layout::from_size_align(size, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());

        let gpa = 0x1000_0000;
        mem.mem_map(gpa, size as u64, host as usize, MemMapOption::default())
            .expect("map");
        mem.unmap(gpa, size as u64).expect("unmap");
        mem.unmap(gpa, size as u64).expect_err("unmap again");

        // SAFETY: `host` came from `alloc_zeroed` with `layout` and is not
        // mapped into the guest anymore.
        unsafe { dealloc(host, layout) };
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_irqchip_created_once() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");
        // Second `KVM_CREATE_IRQCHIP` fails with `EEXIST`.
        vm.enable_irqchip().expect_err("irqchip again");
    }

    #[test]
    fn test_create_vcpus() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        let cpu1 = vm.create_vcpu(1).expect("vcpu 1");
        assert_ne!(cpu0.fd.as_raw_fd(), cpu1.fd.as_raw_fd());
        // Second `KVM_CREATE_VCPU` with the same id fails with `EEXIST`.
        assert!(vm.create_vcpu(0).is_err(), "vCPU 0 created a second time");
    }

    #[test]
    fn test_ioeventfd_registry() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let registry = vm.create_ioeventfd_registry();

        let eventfd = registry.create().expect("ioeventfd");
        registry
            .register(&eventfd, 0x1000, 4, None)
            .expect("bind at 0x1000");
        // Second `KVM_IOEVENTFD` at the address of a `len` 0 ioeventfd fails
        // with `EEXIST`.
        let clash = registry.create().expect("ioeventfd");
        assert!(
            registry.register(&clash, 0x1000, 4, None).is_err(),
            "second ioeventfd bound to the same address"
        );

        registry.deregister(&eventfd).expect("unbind");
        assert!(
            registry.deregister(&eventfd).is_err(),
            "same ioeventfd unbound twice"
        );

        // Ioeventfds with different datamatch values can share an address.
        // Each deassign names its own value.
        let seven = registry.create().expect("ioeventfd");
        let nine = registry.create().expect("ioeventfd");
        registry
            .register(&seven, 0x2000, 2, Some(7))
            .expect("bind on 7");
        registry
            .register(&nine, 0x2000, 2, Some(9))
            .expect("bind on 9");
        registry.deregister(&seven).expect("unbind 7");
        registry.deregister(&nine).expect("unbind 9");

        assert!(
            registry.register(&eventfd, 0x3000, 3, Some(1)).is_err(),
            "three-byte datamatch accepted"
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
        // Check GSI assignment, masking and route removal of irqfds.
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
