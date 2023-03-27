# Changelog

All notable changes to FEVER will be documented in this file.

## [1.3.5] - 2023-03-27

### Fixed
- Properly handle `null` fields in DNS v2 data (#104)

## [1.3.4] - 2022-04-28

### Changed
- Log heartbeat creation with Info level (#100)
- Update Go dependency versions (#99)

### Removed
- Support for Stenosis (#98)

## [1.3.3] - 2022-01-25

### Changed
- Fixed handling of JSON `null` values (#97)

## [1.3.2] - 2021-12-09

### Added
- End-to-end test support
  - Add heartbeat alerts to forwarded events (#94)
  - Add flow report testdata submission (#93)
  - Add passive DNS testdata submission (#92)
- Add option to remove `null` JSON fields when using `fever alertify` (#91)

## [1.3.1] - 2021-11-03

### Fixed
- Ensure that alertified events also contain added fields (#90)

## [1.3.0] - 2021-08-15

### Added
- gRPC based infrastructure for remote runtime communication with FEVER process.
- Runtime control tool for Bloom filter matcher `fever bloom` (#86, #85)

### Changed
- CI now uses GitHub Actions (#87, #81)

## [1.2.0] - 2021-06-25

### Added
- Support for multiple output sockets with event type filtering and
  buffers (#84)

### Changed
- Speed up addition of fields to forwarded EVE-JSON (#83)

## [1.1.0] - 2021-06-09

### Added
- Support for input buffering (#82)

## [1.0.19] - 2021-05-04

### Added
- Support Bloom filter matching for TLS fingerprints (#76, #38)

### Changed
- Reduce log noise by moving AMQP messages to debug log level (#78)

## [1.0.18] - 2021-03-30

### Added
- Added `version` subcommand (#73)

### Changed
- Prevent deadlock on main event stream during reconnect (#75)

## [1.0.17] - 2021-03-04

### Changed
- change timestamp handling when alertifying (#72)

## [1.0.16] - 2021-02-19

### Changed
- Remove potentially blocking calls/locks (#71)
- Use Go modules.

## [1.0.15] - 2021-01-22

### Changed
- Make sure timestamps created by alertifier match regular Suricata timestamps.
- Ensure FEVER starts up with unreachable AMQP endpoint (#69)

## [1.0.14] - 2020-12-04

### Added
- Add heartbeat injector (#67)

## [1.0.13] - 2020-11-05

### Added
- Add flow profiling metrics gathering (#66)

## [1.0.12] - 2020-10-13

### Added
- Add interface filtering for Stenosis connector (#60)
- Add alertify tool (#62)

### Changed
- Various bugfixes (#63, #64)

## [1.0.11] - 2020-08-11

### Added
- CHANGELOG.md now available.
- Add option to inject arbitrary fields into EVE-JSON (#49)

### Changed

- Various code simplifications and robustness improvements.

## [1.0.10] - 2020-06-11

### Changed
- Only extend incoming EVE-JSON instead of marshaling into predefined schema. This enables future-proof consistent output of EVE-JSON as there are no assuptions about what fields are present or allowed in the JSON schema (#54)

### Fixed
- Some bugfixes (such as race conditions).

## [1.0.9] - 2020-05-14

### Added
- Support for interacting with an external persistence tool (Stenosis).

### Changed
Various cleanups as well as test and code simplifications.

## [1.0.8] - 2019-09-19

### Added
- Optional collection of metadata bundles (context) for each alert, to be submitted over a separate AMQP connection (#46)

### Changed
- Flow IDs are now forwarded as strings to work around potential issues with syslog-ng (#48)

## [1.0.7] - 2019-08-06

### Fixed
- Bloom filter alerts might not be properly forwarded (cf. rhaist/surevego@b1cf215)

## [1.0.6] - 2019-08-02

### Added
- Support for active rDNS queries (#36)
- Bloom filter IoC blocking (#44)

### Changed
- Do not use explicit types in InfluxDB submissions (#34)
- Distinguish DNS query and answer in Bloom filter alerting (#40)
- Allow AMQP channel multiplexing (#43)

### Fixed
- Fix bug causing 100% CPU on AMQP reconnect (#43)

## [1.0.5] - 2019-02-14

### Added
- Support for more flexible URL Bloom filter matching (#33)

### Fixed
- Improved stability of tests w.r.t. run time, see (#32 and #31)

## [1.0.4] - 2019-01-25

### Added
- Forwarding can be disabled by setting -o to empty string (#22)
- TLS metadata is included in TLS SNI Bloom filter alert (#26)

### Fixed
- Tests no longer fail intermittently (#27)

### Changed
- All events are sent to the database, not just those unhandled by any additional processors (#29)

## [1.0.3] - 2019-01-11

### Added
- Support for IP alerting via EVE metadata (#18)

### Changed
- Improves robustness of Bloom filter matching by more relaxed handling of corrupted filter input files (#19)

## [1.0.2] - 2018-12-11

### Added
- Configurable Bloom filter prefixes (#16)

## [1.0.1] - 2018-11-12

### Added
- `makeman` subcommand

### Changed
- Do not fail when no config file can be read.
- Do not use DCSO-specific alert prefixes by default for Bloom filter alerts.

## [1.0.0] - 2018-11-09

First proper open-source release.
