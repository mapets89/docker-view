# Changelog

All notable changes are documented here. This project follows Keep a Changelog conventions and intends to use semantic versioning.

## [Unreleased]

### Added

- Initial DockerView V1 implementation: split Server/Gateway architecture, local auth, sessions, RBAC, policies, audit, inspection, stats, risk analysis, masked environment and inspect, SSE logs, xterm terminal, admin UI, hardened Compose, CI, tests, and security documentation.

### Fixed

- Prevented Users, Roles, and Policies listings from deadlocking when SQLite uses a single connection.
- Corrected audit metadata decoding from SQLite text values so existing events can be listed.
- Standardized empty administrative collections as JSON arrays instead of `null`, with defensive handling in the Policies and Audit UI.
- Prevented a cached first-run page from showing administrator setup again after logout.
