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

- x86_64 or riscv64 Linux with KVM enabled, and read/write access to `/dev/kvm`. riscv64 host needs
  AIA, since interrupt controller of a guest is in-kernel APLIC and IMSICs.

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

Flags, only `--kernel` is required:

- `--kernel K`, kernel image, bzImage on x86_64 or Image on riscv64.
- `--initrd I`, initramfs, a cpio archive.
- `--cmdline C`, kernel command line, `console=ttyS0` by default.
- `--memory SIZE`, guest RAM in MiB or with K/M/G suffix, 512M by default.
- `--vcpus N`, number of vCPUs, 1 by default.
- `--disk FILE`, file attached as virtio-blk device, `/dev/vda` in the guest.
- `--network SOCK`, host socket carrying Ethernet frames of a virtio-net device.
- `--mac ADDR`, MAC address of the virtio-net device, needs `--network`.
- `--seccomp MODE`, syscall allowlist of guest threads, `trap` by default, `errno` or `none`.
- `--timeout SECS`, stop the guest after SECS seconds.

Exit codes:

- 0, guest powered off, or ended with `Ctrl-]`.
- 1, usage error.
- 2, failure on host side.
- 3, guest asked for reboot.
- 124, `--timeout` elapsed.
- 128 plus signal number, SIGTERM, SIGINT or SIGHUP stopped the guest.

`lingcore --help` prints the same, `lingcore --version` prints the crate version. No environment
variable is read.

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

Store defaults to `/var/lib/lingcage`, use `--store DIR` or `LINGCAGE_STORE` for another one.

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
`cargo check --target aarch64-unknown-linux-gnu` and `--target x86_64-apple-darwin` make sure the
`cfg` gates are correct. Only x86_64 and riscv64 Linux build the `machine` feature and parts of
`lingcage` on top of it.

## Status

`lingcore` boots a Linux guest with the devices above, captures and clones it. KVM is the only
backend, `x86_64` boots a bzImage with ACPI tables and `riscv64` boots an Image with device tree.
`lingcage` builds a template from a kernel and a guest image, clones it into a sandbox, runs
commands through its agent over vsock and powers the guest off. `lingcage run` is the front end.
Isolation, storage and networking are next milestones.
