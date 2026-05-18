<div align="center">
    <h1>LingCage</h1>
    <p><strong>
        LingCage is a secure agent infrastructure that cages AI agents with
        minimum overhead. It protects systems from both intentional and
        unintentional harmful actions of AI agents.
    </strong></p>
</div>

> **Note:** LingCage is still under heavy development. APIs may change significantly.

## Overview

There are two crates in this repository:

- **lingcore** is a library of primitives:

  - hypervisor traits with KVM backend
  - guest memory
  - direct kernel boot
  - minimal device model
  - per-thread seccomp filters
  - `Machine`, which assembles them into one guest, started, paused, captured and cloned

- **lingcage** is the VMM on top of it, with process model, jailer and command line. Not implemented
  yet, coming soon.

## Getting started

### Prerequisites

- x86_64 Linux with KVM enabled, and read/write access to `/dev/kvm`.

- Rust toolchain, pinned via [rust-toolchain.toml](rust-toolchain.toml). Install via
  [rustup](https://rustup.rs):

  ```console
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

### Using lingcore

Add `lingcore` to your host program with `machine` and `kvm` features enabled:

```toml
[dependencies]
lingcore = { version = "0.1", features = ["machine", "kvm"] }
```

`default` only enables `hv`, the trait layer. `machine` pulls in rest of the library and `kvm` is
the only backend for now.

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

`Config::disk` attaches a file as virtio-blk device, `Config::channel` adds vsock device and
`Config::network` adds virtio-net device.

`Machine` goes through `Created`, `Running`, `Paused` and `Shutdown` states:

- `start` runs each vCPU on its own thread.
- `pause` parks them, `resume` continues them.
- `stop` kicks vCPUs out of the guest.
- `wait` joins the threads and returns exit reason of the first vCPU thread joined.

## Objectives

Generic VMM is not a goal. Firmware boot, Windows guests, device hotplug and PCI are out of scope.
Isolating the VMM process from the host with namespaces, cgroups and privilege dropping is the job
of `lingcage`, not `lingcore`.

## Building and testing

```console
cargo build --workspace --all-targets
cargo test --workspace --all-features
```

Unit tests under `hv`, `boot` and `machine` open `/dev/kvm` and run guest code, so a KVM host is
needed. `cargo check --target aarch64-unknown-linux-gnu` and `--target x86_64-apple-darwin` make
sure the `cfg` gates are correct. Only x86_64 Linux builds the `machine` feature.

## Status

`lingcore` boots a Linux guest with the devices above, captures and clones it. KVM is the only
backend and `x86_64` is the only architecture for now. `lingcage` is coming soon.
