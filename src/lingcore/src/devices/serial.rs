// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! 16550 UART, the guest serial console.

use std::collections::VecDeque;
use std::io::{self, Write};

use crate::hv::irq::IrqSender;

/// Receive buffer on read, transmit holding register on write. Low byte
/// of the divisor while divisor latch is open.
const DATA: u64 = 0;
/// Interrupt enable. High byte of the divisor while the latch is open.
const IER: u64 = 1;
/// Interrupt identification on read, FIFO control on write.
const IIR: u64 = 2;
/// Line control, bit 7 is the divisor latch access bit.
const LCR: u64 = 3;
/// Modem control.
const MCR: u64 = 4;
/// Line status.
const LSR: u64 = 5;
/// Modem status.
const MSR: u64 = 6;
/// Scratch.
const SCR: u64 = 7;

/// Divisor latch access bit of `LCR`.
const LCR_DLAB: u8 = 0x80;
/// `LSR` bit for receive data ready.
const LSR_DATA_READY: u8 = 0x01;
/// `LSR` bits which mark transmit holding and shift registers empty. Both
/// are reported as set, since a byte written to `DATA` reaches `out`
/// within the call.
const LSR_TRANSMIT_EMPTY: u8 = 0x60;
/// `MSR` bits: data carrier detect, data set ready and clear to send.
/// Reported as set since there is no modem behind the port.
const MSR_CONNECTED: u8 = 0xb0;
/// `IER` bit enabling the received data available interrupt.
const IER_DATA_READY: u8 = 0x01;
/// `IER` bit enabling the transmit holding register empty interrupt.
const IER_TRANSMIT_EMPTY: u8 = 0x02;
/// `IIR` value for no interrupt pending.
const IIR_NO_INTERRUPT: u8 = 0x01;
/// `IIR` value for transmit holding register empty interrupt pending.
const IIR_TRANSMIT_EMPTY: u8 = 0x02;
/// `IIR` reports received data available interrupt pending. It is
/// reported ahead of `IIR_TRANSMIT_EMPTY`.
const IIR_DATA_READY: u8 = 0x04;
/// `IIR` bits: FIFOs enabled, which identifies a 16550A.
const IIR_FIFO_ENABLED: u8 = 0xc0;
/// `FCR` bit which enables the FIFOs.
const FCR_ENABLE: u8 = 0x01;

/// 16550 UART. Transmitted bytes are written to `out`, bytes passed to
/// `receive` are queued for the guest to read. `line` is raised for empty
/// transmit register and for queued input, according to `IER` bits.
pub struct Serial<W: Write> {
    out: W,
    input: VecDeque<u8>,
    /// Interrupt line, `None` for a UART without one.
    line: Option<Box<dyn IrqSender>>,
    /// Pending interrupts as `IIR` bits. A reason already pending does not
    /// raise the line again, so a run of bytes only raises it once.
    asking: u8,
    ier: u8,
    fcr: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    divisor: u16,
}

impl<W: Write> Serial<W> {
    /// Create a UART in reset state, transmitting into `out`.
    pub fn new(out: W) -> Self {
        Serial {
            out,
            input: VecDeque::new(),
            line: None,
            asking: 0,
            ier: 0,
            fcr: 0,
            lcr: 0,
            mcr: 0,
            scr: 0,
            // 9600 baud with the 1.8432 MHz reference clock.
            divisor: 12,
        }
    }

    /// Attach `line` as the interrupt line.
    pub fn on_line(mut self, line: Box<dyn IrqSender>) -> Self {
        self.line = Some(line);
        self
    }

    /// Raise the line for `reason` unless it is pending already. Error from
    /// `send` is propagated.
    fn ask_for_attention(&mut self, reason: u8) -> io::Result<()> {
        if self.asking & reason != 0 {
            return Ok(());
        }
        self.asking |= reason;
        match &self.line {
            Some(line) => line.send().map_err(io::Error::other),
            None => Ok(()),
        }
    }

    /// Raise the line for empty transmit register if `IER_TRANSMIT_EMPTY` is
    /// set.
    fn ask_about_transmit(&mut self) -> io::Result<()> {
        if self.ier & IER_TRANSMIT_EMPTY == 0 {
            return Ok(());
        }
        self.ask_for_attention(IIR_TRANSMIT_EMPTY)
    }

    /// Raise the line for queued input if `IER_DATA_READY` is set and there
    /// is byte queued.
    fn ask_about_input(&mut self) -> io::Result<()> {
        if self.ier & IER_DATA_READY == 0 || self.input.is_empty() {
            return Ok(());
        }
        self.ask_for_attention(IIR_DATA_READY)
    }

    /// Queue `bytes` for the guest to read from `DATA` and raise the line
    /// for them.
    pub fn receive(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.input.extend(bytes);
        self.ask_about_input()
    }

    fn latched(&self) -> bool {
        self.lcr & LCR_DLAB != 0
    }

    /// Read the register at `offset`. Registers are one byte wide and one
    /// byte apart, `offset` is taken modulo 8.
    pub fn read(&mut self, offset: u64) -> u8 {
        match offset & 7 {
            DATA if self.latched() => self.divisor as u8,
            DATA => {
                let byte = self.input.pop_front().unwrap_or(0);
                // `IIR` keeps reporting input while bytes remain, the
                // read which empties the queue clears it.
                if self.input.is_empty() {
                    self.asking &= !IIR_DATA_READY;
                }
                byte
            }
            IER if self.latched() => (self.divisor >> 8) as u8,
            IER => self.ier,
            IIR => {
                let fifos = if self.fcr & FCR_ENABLE != 0 {
                    IIR_FIFO_ENABLED
                } else {
                    0
                };
                // Input is reported first and stays pending until `DATA`
                // empties the queue. Reading `IIR` clears the transmit
                // interrupt, and the next byte written raises the line again.
                let reason = if self.asking & IIR_DATA_READY != 0 {
                    IIR_DATA_READY
                } else if self.asking & IIR_TRANSMIT_EMPTY != 0 {
                    self.asking &= !IIR_TRANSMIT_EMPTY;
                    IIR_TRANSMIT_EMPTY
                } else {
                    IIR_NO_INTERRUPT
                };
                fifos | reason
            }
            LCR => self.lcr,
            MCR => self.mcr,
            LSR => {
                let ready = if self.input.is_empty() {
                    0
                } else {
                    LSR_DATA_READY
                };
                LSR_TRANSMIT_EMPTY | ready
            }
            MSR => MSR_CONNECTED,
            _ => self.scr,
        }
    }

    /// Write `value` to the register at `offset`. Write to `LSR` or `MSR` is
    /// dropped. A byte written to `DATA` is written to `out` and flushed.
    /// Error from either, or from raising the line, is propagated.
    pub fn write(&mut self, offset: u64, value: u8) -> io::Result<()> {
        match offset & 7 {
            DATA if self.latched() => {
                self.divisor = (self.divisor & 0xff00) | u16::from(value);
            }
            DATA => {
                self.out.write_all(&[value])?;
                self.out.flush()?;
                // The byte has reached `out`, so transmit register is
                // empty again.
                self.ask_about_transmit()?;
            }
            IER if self.latched() => {
                self.divisor = (self.divisor & 0x00ff) | (u16::from(value) << 8);
            }
            IER => {
                self.ier = value;
                self.ask_about_transmit()?;
                self.ask_about_input()?;
            }
            IIR => self.fcr = value,
            LCR => self.lcr = value,
            MCR => self.mcr = value,
            SCR => self.scr = value,
            _ => {}
        }
        Ok(())
    }
}

impl<W: Write + Send> crate::devices::Device for Serial<W> {
    /// Registers are one byte wide, wider read only returns the register at
    /// `offset`.
    fn read(&mut self, offset: u64, _size: u8) -> u64 {
        u64::from(Serial::read(self, offset))
    }

    /// Wider write stores its lowest byte into the register at `offset`.
    fn write(&mut self, offset: u64, _size: u8, value: u64) -> io::Result<()> {
        Serial::write(self, offset, value as u8)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::devices::serial::*;

    /// Interrupt line which counts its raises.
    #[derive(Clone)]
    struct Counter(Arc<AtomicUsize>);

    impl Counter {
        fn raises(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl IrqSender for Counter {
        fn send(&self) -> crate::hv::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn test_transmit_interrupt_once_per_run() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut uart = Serial::new(Vec::new()).on_line(Box::new(line.clone()));

        // With IER_TRANSMIT_EMPTY clear, bytes do not raise the line.
        for byte in b"the kernel prints this by spinning on the line status" {
            uart.write(DATA, *byte).expect("send a byte");
        }
        assert_eq!(line.raises(), 0, "line raised with IER clear");

        // Register is empty, so enabling it raises the line immediately.
        uart.write(IER, IER_TRANSMIT_EMPTY).expect("enable");
        assert_eq!(line.raises(), 1);

        // Line stays raised until IIR is read, so a run of bytes only raises
        // it once.
        for byte in b"and this goes out through the tty" {
            uart.write(DATA, *byte).expect("send a byte");
        }
        assert_eq!(line.raises(), 1, "line raised per byte");

        // Reading IIR identifies the interrupt and clears it.
        assert_eq!(
            uart.read(IIR) & 0x0f,
            IIR_TRANSMIT_EMPTY,
            "IIR reports no interrupt"
        );
        assert_eq!(
            uart.read(IIR) & 0x0f,
            IIR_NO_INTERRUPT,
            "IIR still reports the interrupt"
        );

        // Next byte raises the line again.
        uart.write(DATA, b'x').expect("send a byte");
        assert_eq!(line.raises(), 2);

        // With IER_TRANSMIT_EMPTY cleared again, byte does not raise the line.
        uart.read(IIR);
        uart.write(IER, 0).expect("disable");
        uart.write(DATA, b'y').expect("send a byte");
        assert_eq!(line.raises(), 2, "line raised after IER cleared");
    }

    #[test]
    fn test_input_interrupt_on_receive() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut uart = Serial::new(Vec::new()).on_line(Box::new(line.clone()));

        // With IER_DATA_READY clear, byte does not raise the line but stays
        // queued.
        uart.receive(b"a").expect("receive a byte");
        assert_eq!(line.raises(), 0, "line raised with IER clear");

        // A byte is queued, so enabling it raises the line immediately.
        uart.write(IER, IER_DATA_READY).expect("enable");
        assert_eq!(line.raises(), 1);

        // Interrupt stays pending until the queue is read empty, so a run of
        // bytes only raises the line once.
        uart.receive(b"bcde").expect("receive a run");
        assert_eq!(line.raises(), 1, "line raised per byte");

        // Reading IIR reports the input, and it stays pending while bytes
        // remain.
        assert_eq!(uart.read(IIR) & 0x0f, IIR_DATA_READY);
        assert_eq!(uart.read(DATA), b'a');
        assert_eq!(
            uart.read(IIR) & 0x0f,
            IIR_DATA_READY,
            "IIR cleared with bytes still queued"
        );

        // Reading the last byte clears it.
        for byte in b"bcde" {
            assert_eq!(uart.read(DATA), *byte);
        }
        assert_eq!(
            uart.read(IIR) & 0x0f,
            IIR_NO_INTERRUPT,
            "IIR still reports input with the queue empty"
        );

        // Next byte raises the line again.
        uart.receive(b"f").expect("receive a byte");
        assert_eq!(line.raises(), 2);

        // With IER_DATA_READY cleared again, byte does not raise the line.
        uart.write(IER, 0).expect("disable");
        uart.read(DATA);
        uart.receive(b"g").expect("receive a byte");
        assert_eq!(line.raises(), 2, "line raised after IER cleared");
    }

    #[test]
    fn test_input_reported_before_transmit() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut uart = Serial::new(Vec::new()).on_line(Box::new(line.clone()));

        // Both enabled, and both pending at the same time.
        uart.write(IER, IER_DATA_READY | IER_TRANSMIT_EMPTY)
            .expect("enable");
        assert_eq!(line.raises(), 1, "empty register did not raise the line");
        uart.receive(b"Z").expect("receive a byte");
        assert_eq!(line.raises(), 2);

        // Input is reported first, empty transmit register is reported once
        // the byte is read.
        assert_eq!(uart.read(IIR) & 0x0f, IIR_DATA_READY);
        assert_eq!(uart.read(DATA), b'Z');
        assert_eq!(
            uart.read(IIR) & 0x0f,
            IIR_TRANSMIT_EMPTY,
            "transmit interrupt lost behind the input"
        );
        assert_eq!(uart.read(IIR) & 0x0f, IIR_NO_INTERRUPT);
    }

    #[test]
    fn test_register_behaviour() {
        // Scratch, status, FIFO and divisor latch registers.
        let mut uart = Serial::new(Vec::new());

        // Scratch register round trip, which drivers use to probe the UART.
        uart.write(SCR, 0xa5).expect("scratch");
        assert_eq!(uart.read(SCR), 0xa5);

        // No input queued, only transmit bits are set, and modem lines set.
        assert_eq!(uart.read(LSR), LSR_TRANSMIT_EMPTY);
        assert_eq!(uart.read(MSR), MSR_CONNECTED);

        // Enabling FIFOs makes IIR identify as 16550A.
        assert_eq!(uart.read(IIR), IIR_NO_INTERRUPT);
        uart.write(IIR, FCR_ENABLE).expect("fifo control");
        assert_eq!(uart.read(IIR), IIR_FIFO_ENABLED | IIR_NO_INTERRUPT);

        // With the latch open, DATA and IER are the divisor. IER itself is
        // kept.
        uart.write(IER, 0x0f).expect("interrupt enable");
        uart.write(LCR, LCR_DLAB).expect("open the latch");
        uart.write(DATA, 0x34).expect("divisor low");
        uart.write(IER, 0x12).expect("divisor high");
        assert_eq!(uart.read(DATA), 0x34);
        assert_eq!(uart.read(IER), 0x12);
        uart.write(LCR, 0x03).expect("close the latch");
        assert_eq!(
            uart.read(IER),
            0x0f,
            "divisor overwrote the enable register"
        );

        // Received byte sets data ready until it is read.
        uart.receive(b"Z").expect("receive a byte");
        assert_eq!(uart.read(LSR), LSR_TRANSMIT_EMPTY | LSR_DATA_READY);
        assert_eq!(uart.read(DATA), b'Z');
        assert_eq!(uart.read(LSR), LSR_TRANSMIT_EMPTY);

        // Writes to status registers are dropped.
        uart.write(LSR, 0).expect("dropped");
        uart.write(MSR, 0).expect("dropped");
        assert_eq!(uart.read(LSR), LSR_TRANSMIT_EMPTY);
        assert_eq!(uart.read(MSR), MSR_CONNECTED);
    }

    #[test]
    fn test_transmit_to_sink() {
        let mut uart = Serial::new(Vec::new());
        for byte in b"hi\n" {
            uart.write(DATA, *byte).expect("transmit");
        }
        let mut out = Vec::new();
        std::mem::swap(&mut out, &mut uart.out);
        assert_eq!(out, b"hi\n");
    }

    /// Guest reads `LSR` and writes it to `DATA`, then reads the queued byte
    /// and writes it as well, so `out` ends up with both.
    #[cfg(all(
        feature = "kvm",
        feature = "vcpu",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn test_guest_console_round_trip() {
        // Run real guest code which reads LSR and echoes queued input.
        use std::alloc::{Layout, alloc_zeroed, dealloc};

        use crate::hv::backend::kvm::hypervisor::KvmHv;
        use crate::hv::hypervisor::Hypervisor;
        use crate::hv::memory::{MemMapOption, VmMemory};
        use crate::hv::vcpu::VmExit;
        use crate::hv::vm::Vm;
        use crate::hv::{Error, Result};
        use crate::vcpu::{VmOps, run};

        /// Port of the first UART on PC.
        const COM1: u16 = 0x3f8;
        const PAGE: usize = 4096;
        const CODE: u64 = 0xffff_f000;

        /// `VmOps` with the UART at `COM1` and no other device.
        struct Console(Serial<Vec<u8>>);

        impl VmOps for Console {
            fn read_port(&mut self, port: u16, _size: u8) -> Result<u32> {
                match port.checked_sub(COM1) {
                    Some(offset) if offset < 8 => Ok(u32::from(self.0.read(u64::from(offset)))),
                    _ => Err(Error::Other("no device at that port")),
                }
            }

            fn write_port(&mut self, port: u16, _size: u8, value: u32) -> Result<()> {
                match port.checked_sub(COM1) {
                    Some(offset) if offset < 8 => self
                        .0
                        .write(u64::from(offset), value as u8)
                        .map_err(|_| Error::Other("console sink write failed")),
                    _ => Err(Error::Other("no device at that port")),
                }
            }

            fn read_mmio(&mut self, _addr: u64, _size: u8) -> Result<u64> {
                Err(Error::Other("no device at this address"))
            }

            fn write_mmio(&mut self, _addr: u64, _size: u8, _value: u64) -> Result<()> {
                Err(Error::Other("no device at this address"))
            }
        }

        let code = [
            0xba, 0xfd, 0x03, // mov dx, 0x3fd
            0xec, // in al, dx
            0xba, 0xf8, 0x03, // mov dx, 0x3f8
            0xee, // out dx, al
            0xec, // in al, dx
            0xee, // out dx, al
            0xf4, // hlt
        ];

        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());
        // Out of reset the vCPU fetches at 0xff0 of this page. The near jump
        // there lands at offset 0, so `code` gets the rest of the page.
        let jump = [0xe9, 0x0d, 0xf0];
        // SAFETY: the allocation is one page, the jump fits at 0xff0 and `code`
        // fits below it.
        unsafe {
            std::ptr::copy_nonoverlapping(jump.as_ptr(), host.add(0xff0), jump.len());
            std::ptr::copy_nonoverlapping(code.as_ptr(), host, code.len());
        }
        mem.mem_map(CODE, PAGE as u64, host as usize, MemMapOption::default())
            .expect("map the reset vector");

        let mut console = Console(Serial::new(Vec::new()));
        console.0.receive(b"Z").expect("receive a byte");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(run(&mut cpu, &mut console).expect("run"), VmExit::Halt);
        assert_eq!(
            console.0.out,
            [LSR_TRANSMIT_EMPTY | LSR_DATA_READY, b'Z'],
            "guest did not write status and the queued byte"
        );

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
    }
}
