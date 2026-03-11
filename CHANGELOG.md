# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Laravel-first JWT package architecture with container-driven runtime
  services and package auto-discovery
- Profile-based issuance and parsing through `JWT::issueFor()` and
  `JWT::parseFor()`
- Published `config/jwt.php` with named profile support for signers,
  keys, TTL, leeway, headers, claims, issuers, and audiences
- Explicit token section contracts and models for claims, headers, and
  signatures
- Laravel service provider and facade integration tests

### Changed
- Moved contracts into `src/Contracts` and renamed interfaces with the
  `Interface` suffix
- Replaced generic dataset-style token structures with clearer token
  section types
- Standardized signer hierarchy naming and moved internal helpers into
  support namespaces
- Adopted Carbon-based time handling across issuance and validation

### Documentation
- Replaced the skeleton README with real package metadata and moved full
  package documentation into `DOCS.md`
