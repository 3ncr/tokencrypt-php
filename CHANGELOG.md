# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-04-22

Stable API for the [3ncr.org v1](https://3ncr.org/1/) encryption envelope
(AES-256-GCM, 12-byte random IV, 16-byte GCM tag), aligned with the tiered KDF
guidance in the spec.

### Added

- `TokenCrypt::fromRawKey($key)` — primary constructor for callers with a
  32-byte AES-256 key.
- `TokenCrypt::fromArgon2id($secret, $salt)` — Argon2id KDF for
  password-strength secrets, via libsodium. Parameters match the
  [3ncr.org v1 spec](https://3ncr.org/1/#kdf): `m=19456 KiB, t=2, p=1`,
  32-byte output, 16-byte salt.

### Changed

- `new TokenCrypt($secret, $salt, $iterations)` (PBKDF2-SHA3) is now documented
  as legacy; kept for backward compatibility with data encrypted by earlier
  versions. Prefer `fromRawKey` or `fromArgon2id` for new code.
- Minimum PHP bumped from 7.2 to 8.1. CI matrix now covers PHP 8.1–8.5.
- `ext-sodium` added to required extensions (used by `fromArgon2id`).
- PHPUnit bumped from `^8.5` to `^10.5`; php-cs-fixer bumped to `^3.95`.
- Migrated CI from Travis to GitHub Actions.

[2.0.0]: https://github.com/3ncr/tokencrypt-php/releases/tag/v2.0.0
