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
lingcore = { version = "0.1", features = ["machine", "kvm"] }
```

Library usage and the `lingcore` binary are described in
[src/lingcore/README.md](src/lingcore/README.md).

### Using lingcage

`lingcage` runs a command in a guest cloned from a template, which is a captured boot of a kernel
and a guest image carrying `lingcage-agent`. Build the image first, then build the front end:

```console
cargo build --release -p lingcage --features cli --bin lingcage
```

`lingcage check` lists host prerequisites, `template build` boots the guest once and registers the
capture, and `run` clones it, runs the command and exits with status of the command:

```console
$ lingcage check --kernel bzImage
$ lingcage template build --kernel bzImage --initrd initramfs.cpio.gz --memory 256M --vcpus 1 \
      --name base
$ lingcage run --template base -- sh -c 'echo hello from $(hostname)'
```

Store defaults to `/var/lib/lingcage`, use `--store DIR` or `LINGCAGE_STORE` for another one. `-v`,
`--log-file FILE` and `--event-monitor SPEC` are flags of the program, given ahead of the verb or
after it, up to `--`. Log lines are those of lingcore, and `-vv` adds diagnostics of the agent.
`--event-monitor path=FILE` or `fd=N` writes one JSON line per event, for a program driving many
sandboxes. Events are a template built, a sandbox starting, ready with timings of its agent, and
stopped with what ended it, each with a timestamp.

Exit codes follow convention of shell:

- 126, command is not executable.
- 127, command not found.
- 137, command killed by timeout.
- 1, usage error.
- 2, operational failure.

To do the same from a Rust program, enable the `sandbox` feature:

```toml
[dependencies]
lingcage = { version = "0.1", features = ["sandbox"] }
```

```rust
use std::io::Write as _;
use std::time::Duration;

use lingcage::hv::Hv;
use lingcage::sandbox::Sandbox;
use lingcage::sandbox::exec::Command;
use lingcage::sandbox::spec::SandboxSpec;
use lingcage::template::TemplateStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hv = Hv::open()?;
    let store = TemplateStore::open("/var/lib/lingcage")?;
    let template = store.get(&"base".into())?;
    let spec = SandboxSpec::for_template(&template);
    // A started sandbox runs no command until its agent has connected.
    let sandbox = Sandbox::start(&hv, &template, &spec)?.ready(Duration::from_secs(5))?;

    let mut process = sandbox.exec(Command::new("sh").args(["-c", "read line; echo got $line"]))?;
    // The stream closes with the handle, and the command reads EOF.
    process.stdin.take().expect("a stdin stream").write_all(b"hello\n")?;
    let output = process.wait_with_output()?;
    print!("{}", String::from_utf8_lossy(&output.stdout));

    // The guest is asked to power off, and stopped after five seconds if it has not.
    let exit = sandbox.shutdown(Duration::from_secs(5))?;
    println!("{exit:?}");
    Ok(())
}
```

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
