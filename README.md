<div align="center">
    <img src="assets/logo.svg" alt="LingCage" width="160">
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

- **lingcage** is the VMM on top of it:

  - templates captured from booted guest
  - sandboxes cloned from them in calling process
  - guest agent which host runs commands through
  - `lingcage` command line

  Process model and jailer are next.

## Getting started

### Prerequisites

- aarch64, x86_64 or riscv64 Linux with KVM enabled, and read/write access to `/dev/kvm`. aarch64
  host needs GICv3, since interrupt controller of a guest is in-kernel distributor and
  redistributors. riscv64 host needs AIA, since controller there is in-kernel APLIC and IMSICs.

- Rust toolchain, pinned via [rust-toolchain.toml](rust-toolchain.toml). Install via
  [rustup](https://rustup.rs):

  ```console
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

### Using lingcore

Add `lingcore` to your host program with `machine` and `kvm` features enabled:

```toml
[dependencies]
lingcore = { version = "0.2", features = ["machine", "kvm"] }
```

Library usage and the `lingcore` binary are described in
[src/lingcore/README.md](src/lingcore/README.md).

### Using lingcage

Add `lingcage` to your host program with the `sandbox` feature enabled:

```toml
[dependencies]
lingcage = { version = "0.2", features = ["sandbox"] }
```

Library usage and the `lingcage` binary are described in
[src/lingcage/README.md](src/lingcage/README.md).

## Objectives

Generic VMM is not a goal. Firmware boot, Windows guests, device hotplug and PCI are out of scope.
Isolating the VMM process from the host with namespaces, cgroups and privilege dropping is the job
of `lingcage`, not `lingcore`.

## Building and testing

```console
features=lingcage/agent,lingcage/cli,lingcore/machine,lingcore/kvm
cargo build --workspace --all-targets --features $features
cargo test --workspace --features $features
```

`--all-features` is not used anywhere. Unit tests under `hv`, `boot` and `machine` of `lingcore` and
under `sandbox` of `lingcage` open `/dev/kvm` and run guest code, so a KVM host is needed.
`cargo check --target aarch64-unknown-linux-gnu`, `--target riscv64gc-unknown-linux-gnu` and
`--target x86_64-apple-darwin` make sure the `cfg` gates are correct, the darwin one because only
Linux builds the `machine` feature and parts of `lingcage` on top of it. An aarch64 guest is
verified under QEMU with `-machine virt,virtualization=on`, which offers EL2 so that KVM runs inside
the emulated machine.

## Status

`lingcore` boots a Linux guest with the devices above, captures and clones it. KVM is the only
backend, `x86_64` boots a bzImage with ACPI tables while `aarch64` and `riscv64` boot an Image with
device tree. `lingcage` builds a template from a kernel and a guest image, clones it into a sandbox,
runs commands through its agent over vsock and powers the guest off. `lingcage run` is the front
end. Isolation, storage and networking are next milestones.
