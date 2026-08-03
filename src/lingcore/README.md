# lingcore

**Building blocks for agentic-workload VMMs.**

[![crates.io](https://img.shields.io/crates/v/lingcore.svg)](https://crates.io/crates/lingcore)
[![docs.rs](https://img.shields.io/docsrs/lingcore)](https://docs.rs/lingcore)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/RuoqingHe/lingcage/blob/main/LICENSE)

## Overview

`lingcore` is a library of VMM primitives for agentic workloads, many short-lived guests cloned from
a template to run untrusted code. It is a library instead of a VMM, and each component is gated
behind a Cargo feature. A `lingcore` binary, built with the `cli` feature, boots a guest from the
command line. API documentation is on [docs.rs](https://docs.rs/lingcore).

- Hypervisor traits with KVM backend (`hv`, `kvm`).
- Guest memory, held as vm-memory regions (`mem`).
- Direct kernel boot, a bzImage with ACPI tables on x86_64, an Image with device tree on aarch64 and
  riscv64 (`boot`, `acpi`, `fdt`).
- Minimal device model, serial port and virtio block, filesystem, console, network and vsock devices
  (`devices`, `virtio`, `netstack`).
- Per-thread seccomp filters confining the threads which serve the guest (`seccomp`).
- `Machine`, which assembles them into one guest, started, paused, captured and cloned (`machine`).

`default` only enables `hv`, the trait layer. `machine` pulls in rest of the library and `kvm` is
the only backend for now.

## Requirements

- aarch64, x86_64 or riscv64 Linux with KVM enabled, and read/write access to `/dev/kvm`. aarch64
  host needs GICv3, since interrupt controller of a guest is in-kernel distributor and
  redistributors. riscv64 host needs AIA, since controller there is in-kernel APLIC and IMSICs.
- Rust toolchain pinned by
  [rust-toolchain.toml](https://github.com/RuoqingHe/lingcage/blob/main/rust-toolchain.toml) of the
  repository.

## Usage

### Using lingcore

Add `lingcore` to your host program with `machine` and `kvm` features enabled:

```toml
[dependencies]
lingcore = { version = "0.1", features = ["machine", "kvm"] }
```

Following program boots the guest, captures it after it is paused, and starts a clone from the
capture:

```rust
use lingcore::hv::backend::kvm::hypervisor::KvmHv;
use lingcore::machine::snapshot::Snapshot;
use lingcore::machine::{Config, Machine};
use lingcore::seccomp::Refusal;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hv = KvmHv::new()?;

    // Need to supply a working `kernel`.
    let config = Config {
        kernel: "/path/to/kernel".into(),
        initrd: Some("rootfs.cpio".into()),
        cmdline: "console=ttyS0".into(),
        memory: 512 << 20,
        vcpus: 2,
        confine: Some(Refusal::Trap),
        ..Default::default()
    };

    // Serial output goes to any `Write`; `console()` takes input for the
    // guest once it is up.
    let mut machine = Machine::new(&hv, &config, std::io::stdout())?;
    machine.start()?;

    // A paused guest is captured in two parts: the registers, interrupt
    // controller, clock and device state as JSON, and the RAM as raw bytes.
    machine.pause()?;
    let snapshot = machine.capture()?;
    machine.write_memory(&mut std::fs::File::create("guest.mem")?)?;
    snapshot.write_to(&mut std::fs::File::create("guest.json")?)?;
    machine.stop()?;
    machine.wait()?;

    // A clone maps the RAM file copy-on-write and continues from the capture.
    let snapshot = Snapshot::read_from(&mut std::fs::File::open("guest.json")?)?;
    let template = std::fs::File::open("guest.mem")?;
    let mut clone = Machine::cloned(&hv, &config, std::io::stdout(), &template)?;
    clone.restore(&snapshot)?;
    clone.start()?;
    clone.wait()?;
    Ok(())
}
```

`Config::disks` attaches files as virtio-blk devices, `/dev/vda` onwards in the guest.
`Config::shares` serves directories of the host over virtio-fs, each under a tag the guest mounts
by. `Config::ports` names ports of a virtio console, each with the socket of its host end.
`Config::channel` adds vsock device and `Config::network` adds virtio-net device.

Only RAM of a clone is copy-on-write. A restored guest takes its filesystem state from captured RAM,
so it needs the disk as capture left it. Copy the disk while the guest is paused, keep that copy
untouched, and give each clone its own copy. Two clones over one disk corrupt the filesystem between
them, and neither reports an error.

`Machine` goes through `Created`, `Running`, `Paused` and `Shutdown` states:

- `start` runs each vCPU on its own thread.
- `pause` parks them, `resume` continues them.
- `stop` kicks vCPUs out of the guest. `stop_handle` gives that kick to a thread which does not own
  the machine.
- `wait` joins the threads and returns exit reason of the first vCPU thread joined.

### Booting a guest with the lingcore binary

`lingcore` binary boots a plain guest from a kernel image with its serial console on the terminal.
It is built with the `cli` feature:

```console
cargo build --release -p lingcore --features cli --bin lingcore
```

`lingcore` boots the kernel, guest output goes to stdout and keys typed on the terminal go to the
guest. Terminal is put into raw mode, so `Ctrl-C` goes to the guest and `Ctrl-]` ends it instead.
When stdin is not a terminal, it is forwarded to the guest until EOF:

```console
$ lingcore --kernel bzImage --initrd initramfs.cpio.gz --vcpus 2 --memory 1G
```

`lingcore --help` lists the flags and exit codes.

## License

Apache-2.0, see [LICENSE](https://github.com/RuoqingHe/lingcage/blob/main/LICENSE) in the
repository.
