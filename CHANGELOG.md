# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Calendar Versioning](https://calver.org/).

## [Unreleased]

## [2026.1.0] - 2026-01-20

### Added

- (users) file header retrieval progress is now displayed by default
- (users) file header addition progress is now displayed by default
- file header retrieval progress is now displayed by default (i.e. when `--progress` is toggled on)
- file header addition progress is now displayed by default (i.e. when `--progress` is toggled on)

### Removed

- omitted separate tests for download body slicer, now tested in new `test_common.py`

### Changed

- (users) download performance for s3 downloads is now improved after moving to use s3 presigned URLs
- download body slicer refactored to `sd_lock_util.common` as the same function can now be used by both `swift` and `s3` implementations
- s3 downloads now use presigned URLs and normal `aiohttp` get requests, should improve download performance

## [2025.12.1] - 2025-12-18

### Fixed

- (users) self-shared buckets no longer fail due to missing whitelist entry
- self-shared buckets no longer try to use the owner parameter with own project

## [2025.12.0] - 2025-12-05

### Added

- (users) sd-migrate-headers command can be used to migrate headers between bucket copies
- sd-migrate-headers command can be used to migrate headers between bucket copies


[Unreleased]: https://gitlab.ci.csc.fi/sds-dev/sd-connect/sd-lock-util/compare/2026.1.0...HEAD
[2026.1.0]: https://gitlab.ci.csc.fi/sds-dev/sd-connect/sd-lock-util/compare/2025.12.1...2026.1.0
[2025.12.1]: https://gitlab.ci.csc.fi/sds-dev/sd-connect/sd-lock-util/compare/2025.12.0...2025.12.1
[2025.12.0]: https://gitlab.ci.csc.fi/sds-dev/sd-connect/sd-lock-util/-/releases/2025.12.0
