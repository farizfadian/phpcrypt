# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

PHPCrypt was run against the other libraries of the family for the first time. With default
settings all three modes already matched; the fixes below cover what did not.

### Fixed

- **`Encryptor` with a key size of 16 or 24 bytes now matches GoCrypt.** 1.0.0 always used
  AES-256-GCM and OpenSSL silently zero-padded the shorter key, so those values could not be read
  by GoCrypt, RustCrypt, NodeCrypt or PyCrypt, and theirs could not be read by PHPCrypt. A 16-byte
  key now selects AES-128-GCM and a 24-byte key AES-192-GCM. The default (32 bytes, AES-256-GCM)
  writes exactly the same bytes as before.
  - Values written by 1.0.0 with any key size still decrypt: `decrypt()` tries the family format
    first, then the 1.0.0 layout. The GCM tag tells them apart.
  - Values written with a key size of 16 or 24 from this version on cannot be read by
    PHPCrypt 1.0.0.
  - `encrypt()` now rejects a key size other than 16, 24 or 32. 1.0.0 accepted any size and
    silently produced AES-256 output.
- **The string `"0"` is accepted as a value and as a password**, as in GoCrypt. 1.0.0 treated it as
  empty: `encrypt('0')` and `new Encryptor('0')` threw, `phpcrypt encrypt -v 0` failed, and
  `phpcrypt encrypt-file` left `KEY=0` unencrypted.
- `Encryptor::decrypt()` rejects input shorter than salt + nonce + tag with a clear message.

### Changed

- **Documentation: `JasyptStrongEncryptor` is not Java compatible.** The README, the docblocks and
  the CLI help said it was. It is the family's own strong format; real Jasypt 1.9.3
  `PBEWithHmacSHA256AndAES_256` cannot read it and it cannot read Jasypt. Use `JasyptEncryptor`
  when Java must read the value. No code changed here.
- The README now lists what was actually tested, with versions, and documents the OpenSSL legacy
  provider that `JasyptEncryptor` needs.

### Added

- Golden-vector tests against GoCrypt v1.0.0: every vector decrypts, and every fixed-salt vector is
  reproduced byte for byte.
- Live round-trip tests, both directions, against GoCrypt, RustCrypt, NodeCrypt, PyCrypt and the
  real Java Jasypt jar, plus a CI job that runs them on Linux and fails if any test is skipped.
- Tests for values written by PHPCrypt 1.0.0 and for the command-line tool.

### Tests

- `UtilsTest` moved to its own file. PHPUnit 10 never ran it while it shared `EncryptorTest.php`.
- The DES wrong-password test no longer fails at random. DES-CBC has no integrity check, so a
  wrong password returns garbage instead of throwing about 1 time in 256.

---

## [1.0.0] - 2024-12-28

### 🎉 Initial Release

First public release of PHPCrypt - Jasypt-like encryption for PHP.

### Added

#### Core Features
- **AES-256-GCM Encryption** (`Encryptor`) - Modern, secure encryption for new projects
- **Jasypt Compatible** (`JasyptEncryptor`) - PBEWithMD5AndDES for Java Jasypt compatibility
- **Jasypt Strong** (`JasyptStrongEncryptor`) - PBEWithHmacSHA256AndAES_256

#### ENC(...) Pattern
- `ENC(base64value)` format matching Jasypt/Spring Boot
- `Utils::isEncrypted()` helper function
- `encryptWithPrefix()` and `decryptPrefixed()` methods

#### Config Loaders
- `.env` file loader with auto-decryption
- JSON file loader with recursive decryption
- `setToEnv()` to load config to environment variables

#### Batch Operations
- `decryptMap()` - Decrypt all values in an array
- `decryptAllInString()` - Decrypt all ENC(...) values in a string

#### CLI Tool
- `phpcrypt encrypt` - Encrypt single value
- `phpcrypt decrypt` - Decrypt single value
- `phpcrypt encrypt-file` - Encrypt all values in a file
- `phpcrypt decrypt-file` - Decrypt all ENC(...) values in a file
- Support for `--jasypt` and `--jasypt-strong` flags
- Support for `PHPCRYPT_PASSWORD` environment variable

#### Cross-Language Compatibility
- Compatible with GoCrypt (Go)
- Compatible with PyCrypt (Python)
- Compatible with NodeCrypt (Node.js)
- Compatible with Java Jasypt
- Shared `ENC(...)` format across all languages

### Requirements
- PHP 8.0+
- ext-openssl

---

Made with ❤️ from Claude AI for PHP developers who need Jasypt
