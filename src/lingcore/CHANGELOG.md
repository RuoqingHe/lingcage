# Changelog

## Unreleased

### Added

- \[[#4](https://github.com/RuoqingHe/lingcage/pull/4)\] Add read-only disks: take `:ro` on
  `--disk`, open the file read-only and offer `VIRTIO_BLK_F_RO`.
- \[[#5](https://github.com/RuoqingHe/lingcage/pull/5)\] Add configuration change interrupt: a
  restore which finds a device's configuration moved raises `VIRTIO_MMIO_INT_CONFIG`.
- \[[#7](https://github.com/RuoqingHe/lingcage/pull/7)\] Add metadata service to a guest:
  `--metadata ADDR=FILE` serves the JSON in FILE at ADDR, tokens as in MMDS V2. The `mmds` feature
  carries it, and the binary is built with it.
- \[[#10](https://github.com/RuoqingHe/lingcage/pull/10)\] Add stop on a lost template page: a clone
  whose RAM image lost a page is stopped and `Error::LostPage` reported.
- \[[#12](https://github.com/RuoqingHe/lingcage/pull/12)\] Add dirty page log to guest RAM:
  `GuestRam::mark` and `written` name the pages written since assembly.
- \[[#12](https://github.com/RuoqingHe/lingcage/pull/12)\] Add dirty page capture:
  `Machine::write_dirty` and the `snapshot` order with `"pages":"dirty"` write the pages written
  since assembly and skip the rest.
- \[[#13](https://github.com/RuoqingHe/lingcage/pull/13)\] Introduce balloon device: pages the guest
  reports free are dropped on the host.
- \[[#13](https://github.com/RuoqingHe/lingcage/pull/13)\] Add balloon to a guest: `Config::balloon`
  and `--balloon` place the device.
- \[[#14](https://github.com/RuoqingHe/lingcage/pull/14)\] Add rate limit to a disk: `Disk::rate`,
  and `,bytes=N` and `,ops=N` on `--disk`, cap bytes and requests a second.

### Changed

- \[[#2](https://github.com/RuoqingHe/lingcage/pull/2)\] Pin rust toolchain version to 1.98.1
  explicitly.
- \[[#4](https://github.com/RuoqingHe/lingcage/pull/4)\] `Config::disks` takes `Disk` in place of
  `PathBuf`, breaking the 0.2.0 API.
- \[[#9](https://github.com/RuoqingHe/lingcage/pull/9)\] Drop kernel requirement under `--restore`:
  a clone takes its kernel from the RAM image.
- \[[#14](https://github.com/RuoqingHe/lingcage/pull/14)\] `--disk` takes `,ro` in place of `:ro`.

### Fixed

- \[[#1](https://github.com/RuoqingHe/lingcage/pull/1)\] Fix template length of block device.
- \[[#2](https://github.com/RuoqingHe/lingcage/pull/2)\] Fix four reads rustc 1.98 refuses: drop
  three unused imports and take a constant chunk by `as_chunks_mut`.
- \[[#8](https://github.com/RuoqingHe/lingcage/pull/8)\] Fix resume refused on a running guest: a
  guest resumed twice is left running.
- \[[#10](https://github.com/RuoqingHe/lingcage/pull/10)\] Fix exit code under `--control`: a guest
  stopped on `--timeout` or by the escape key exits 124 and 0, as it does without a control socket.
