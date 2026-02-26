# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
