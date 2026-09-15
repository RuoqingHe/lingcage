# Changelog

## Unreleased

### Changed

- [#2] Pin rust toolchain version to 1.98.1 explicitly.

### Fixed

- [#1] Fix template length of block device.
- [#2] Fix four reads rustc 1.98 refuses: drop three unused imports and take a constant chunk by
  `as_chunks_mut`.
