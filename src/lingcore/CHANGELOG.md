# Changelog

## Unreleased

### Added

- [#4] Add read-only disks: take `:ro` on `--disk`, open the file read-only and offer
  `VIRTIO_BLK_F_RO`.
- [#5] Add configuration change interrupt: a restore which finds a device's configuration moved
  raises `VIRTIO_MMIO_INT_CONFIG`.

### Changed

- [#2] Pin rust toolchain version to 1.98.1 explicitly.
- [#4] `Config::disks` takes `Disk` in place of `PathBuf`, breaking the 0.2.0 API.

### Fixed

- [#1] Fix template length of block device.
- [#2] Fix four reads rustc 1.98 refuses: drop three unused imports and take a constant chunk by
  `as_chunks_mut`.
