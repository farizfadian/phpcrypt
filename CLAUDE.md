# CLAUDE.md - Complete Development Context for PHPCrypt

> **IMPORTANT**: This file contains ALL context needed for Claude AI to understand and work on PHPCrypt.

---

## Project Summary

**PHPCrypt** is a Jasypt-like encryption library for PHP, part of a cross-language encryption family.

```
Owner       : Fariz Fadian (github.com/farizfadian)
Repository  : github.com/farizfadian/phpcrypt
Language    : PHP 8.1+
License     : MIT
Package     : farizfadian/phpcrypt (Packagist)
Dependencies: ext-openssl (PHP built-in)
Dev Deps    : phpunit/phpunit ^10.0
Created     : December 2024
```

---

## Cross-Language Family (ALL SAME ENC() FORMAT!)

| Project | Repository | Language | Package |
|---------|-----------|----------|---------|
| GoCrypt | github.com/farizfadian/gocrypt | Go 1.21+ | Go module |
| PyCrypt | github.com/farizfadian/pycrypt | Python 3.8+ | pycrypt-jasypt (PyPI) |
| NodeCrypt | github.com/farizfadian/nodecrypt | Node.js 18+ | nodecrypt-jasypt (npm) |
| **PHPCrypt** | github.com/farizfadian/phpcrypt | **PHP 8.1+** | **farizfadian/phpcrypt** |
| Jasypt | jasypt.org | Java | org.jasypt (Maven) |

**ALL USE JasyptEncryptor FOR CROSS-LANGUAGE COMPATIBILITY!**

---

## Project Structure

```
phpcrypt/
├── src/
│   ├── Encryptor.php              # AES-256-GCM - NOT Java compatible
│   ├── JasyptEncryptor.php        # PBEWithMD5AndDES - Java compatible
│   ├── JasyptStrongEncryptor.php  # PBEWithHmacSHA256AndAES_256 - Java compatible
│   ├── ConfigLoader.php           # Load .env, JSON with auto-decrypt
│   └── Utils.php                  # isEncrypted(), ENC_PREFIX, ENC_SUFFIX, ENC_PATTERN
├── bin/
│   └── phpcrypt                   # CLI tool (#!/usr/bin/env php)
├── tests/
│   ├── EncryptorTest.php          # AES-256-GCM tests
│   ├── JasyptCompatTest.php       # Jasypt compatibility tests (has skipIfDesNotAvailable)
│   └── ConfigLoaderTest.php       # Config loader tests
├── .github/workflows/
│   └── ci.yml                     # Test PHP 8.1/8.2/8.3 x Ubuntu/macOS/Windows + coverage
├── composer.json                  # farizfadian/phpcrypt, php >=8.1
├── phpunit.xml                    # PHPUnit 10 config
└── README.md
```

---

## Three Encryptors

| Class | Algorithm | Java Compatible? | When to Use |
|-------|-----------|------------------|-------------|
| `Encryptor` | AES-256-GCM | NO | New PHP-only projects |
| `JasyptEncryptor` | PBEWithMD5AndDES | YES | Cross-language config sharing |
| `JasyptStrongEncryptor` | PBEWithHmacSHA256AndAES_256 | YES | Jasypt strong mode |

### Constructor Signatures

```php
// AES-256-GCM (PHP only)
new Encryptor(string $password, int $iterations = 10000, int $saltSize = 16, int $keySize = 32)

// Jasypt default (Java compatible) - PBEWithMD5AndDES
new JasyptEncryptor(string $password, int $iterations = 1000)

// Jasypt strong (Java compatible) - AES-256-CBC with PBKDF2
new JasyptStrongEncryptor(string $password, int $iterations = 1000, int $saltSize = 16)
```

### Common Methods (all three encryptors)
```php
encrypt(string $plaintext): string              // Returns base64
encryptWithPrefix(string $plaintext): string    // Returns ENC(base64)
decrypt(string $encoded): string                // Decrypts base64
decryptPrefixed(string $value): string          // Decrypts ENC(base64)
decryptMap(array $map): array                   // Decrypt all ENC() values
decryptAllInString(string $input): string       // Decrypt all ENC() in a string
```

---

## Commands

```bash
# Install dependencies
composer install

# Test
composer test

# Test with coverage
vendor/bin/phpunit --coverage-clover coverage.xml

# CLI usage
./bin/phpcrypt encrypt -p password -v "secret"
./bin/phpcrypt encrypt -p password -v "secret" --jasypt
./bin/phpcrypt decrypt -p password -v "ENC(xxx)"
./bin/phpcrypt encrypt-file -p password -i .env.plain -o .env.encrypted

# CLI env var: PHPCRYPT_PASSWORD
```

---

## API Reference

```php
use PHPCrypt\JasyptEncryptor;
use PHPCrypt\JasyptStrongEncryptor;
use PHPCrypt\ConfigLoader;
use PHPCrypt\Utils;

// Jasypt compatible (for BizCore / cross-language)
$enc = new JasyptEncryptor($password);
$encrypted = $enc->encryptWithPrefix($plaintext);   // ENC(...)
$plaintext = $enc->decryptPrefixed('ENC(...)');
$decryptedMap = $enc->decryptMap($configArray);
$decryptedStr = $enc->decryptAllInString($configStr);

// Check if encrypted
Utils::isEncrypted('ENC(abc123)');  // true

// Config loading
$loader = new ConfigLoader($password);
$config = $loader->loadEnvFile('.env');
```

---

## OpenSSL Legacy Provider (CRITICAL)

### The Problem
JasyptEncryptor uses DES-CBC (PBEWithMD5AndDES). OpenSSL 3.0+ (used by PHP 8.2+ on some platforms) disables DES by default.

### CI Solution: Custom openssl.cnf
CI creates a custom openssl.cnf file and sets `OPENSSL_CONF` env var. This works uniformly across all platforms:

**Unix (Linux/macOS):**
```bash
printf "openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n..." > openssl-legacy.cnf
echo "OPENSSL_CONF=${{ github.workspace }}/openssl-legacy.cnf" >> $GITHUB_ENV
```

**Windows (PowerShell):**
```powershell
$conf = "openssl_conf = openssl_init`n[openssl_init]`nproviders = provider_sect`n..."
$conf | Set-Content -Path $confPath -NoNewline
echo "OPENSSL_CONF=$confPath" >> $env:GITHUB_ENV
```

### Test Graceful Degradation: skipIfDesNotAvailable()
All JasyptEncryptor tests call this helper that skips tests when DES is unavailable:
```php
private function skipIfDesNotAvailable(): void
{
    $ciphers = openssl_get_cipher_methods();
    if (!in_array('des-cbc', $ciphers, true)) {
        $this->markTestSkipped('DES-CBC not available');
    }
    // Also check that it actually works (some systems list it but fail)
    $result = @openssl_encrypt('test', 'des-cbc', '12345678', OPENSSL_RAW_DATA, '12345678');
    if ($result === false) {
        $this->markTestSkipped('DES-CBC listed but not functional');
    }
}
```

**Why two checks?** Some systems list `des-cbc` in `openssl_get_cipher_methods()` but the actual encrypt call fails because the legacy provider DLL/SO is missing (common on Windows with shivammathur/setup-php).

---

## Known Issues & Fixes Applied

### 1. Windows PHP 8.2/8.3 - DES May Not Work
`shivammathur/setup-php` on Windows doesn't always include the OpenSSL legacy provider DLL. DES tests are gracefully skipped via `skipIfDesNotAvailable()`.

### 2. macOS sed -i Incompatibility (Fixed)
BSD `sed -i` requires a backup extension argument unlike GNU sed. Fixed by using `printf` to create openssl.cnf instead of `sed -i` on existing files.

### 3. DES Wrong Password - No Guaranteed Throw
DES-CBC has NO integrity check (unlike AES-GCM). Decrypting with wrong password may produce garbage instead of throwing.

### 4. No Release Workflow
PHPCrypt has CI only (no automated Packagist publish). Publishing to Packagist is done via webhook from GitHub.

---

## CI Configuration (ci.yml)

### Test Matrix
- **PHP versions**: 8.1, 8.2, 8.3
- **OS**: ubuntu-latest, windows-latest, macos-latest
- **Total**: 9 test combinations (all green)
- **Extensions**: openssl, xdebug (for coverage)

### Coverage Job
- Runs on ubuntu-latest with PHP 8.2
- Generates coverage.xml (Clover format)
- Uploads to Codecov

---

## Namespace & Autoloading

- **Namespace**: `PHPCrypt\`
- **Autoload**: PSR-4, maps to `src/`
- **PHPUnit bootstrap**: `vendor/autoload.php`

---

<p align="center"><b>An idea from <a href="https://github.com/farizfadian">Fariz</a> and made with love by <a href="https://claude.ai">Claude AI</a></b></p>
