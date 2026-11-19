# PHPCrypt 🔐

[![CI](https://github.com/farizfadian/phpcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/farizfadian/phpcrypt/actions/workflows/ci.yml)
[![Latest Version](https://img.shields.io/packagist/v/farizfadian/phpcrypt.svg)](https://packagist.org/packages/farizfadian/phpcrypt)
[![PHP Version](https://img.shields.io/packagist/php-v/farizfadian/phpcrypt.svg)](https://packagist.org/packages/farizfadian/phpcrypt)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Jasypt-like encryption library for PHP** - Encrypt your application configuration with the familiar `ENC(...)` pattern used in Spring Boot applications.

> **Made with ❤️ from Claude AI for PHP developers who need Jasypt**

---

## 🎯 Why PHPCrypt?

If you're coming from Java/Spring Boot world and need to share encrypted configuration across multiple languages, PHPCrypt is for you! It provides:

- ✅ **Familiar `ENC(...)` pattern** - Just like Jasypt in Spring Boot
- ✅ **Java Jasypt compatibility** - Reads and writes Jasypt's default algorithm (`PBEWithMD5AndDES`)
- ✅ **Multiple algorithms** - From legacy Jasypt to modern AES-256-GCM
- ✅ **Laravel/Symfony ready** - Easy integration with PHP frameworks
- ✅ **CLI tool included** - Encrypt/decrypt from command line
- ✅ **Cross-language** - The same values as GoCrypt, RustCrypt, NodeCrypt and PyCrypt, [tested in CI against all four](#-what-has-actually-been-tested)

---

## 📦 Installation

```bash
composer require farizfadian/phpcrypt
```

---

## 🚀 Quick Start

### Basic Encryption/Decryption

```php
<?php

use PHPCrypt\Encryptor;

// Create encryptor with password
$enc = new Encryptor('mySecretPassword');

// Encrypt
$encrypted = $enc->encryptWithPrefix('db_password_123');
echo $encrypted; // ENC(base64encodedvalue...)

// Decrypt
$decrypted = $enc->decryptPrefixed($encrypted);
echo $decrypted; // db_password_123
```

### Loading Encrypted Configuration

```php
<?php

use PHPCrypt\ConfigLoader;

// .env file:
// DATABASE_HOST=localhost
// DATABASE_PASSWORD=ENC(AbCdEf123456...)

$loader = new ConfigLoader(getenv('PHPCRYPT_PASSWORD'));
$config = $loader->loadEnvFile('.env');

echo $config['DATABASE_PASSWORD']; // actual_password
```

---

## 🔐 Encryption Algorithms

| Encryptor | Algorithm | Security | Java Jasypt can read it? | Use Case |
|-----------|-----------|----------|--------------------------|----------|
| `Encryptor` | AES-256-GCM + PBKDF2-HMAC-SHA256 | ⭐⭐⭐⭐⭐ | ❌ No | **Recommended** when only family libraries read the value |
| `JasyptStrongEncryptor` | AES-256-CBC + PBKDF2-HMAC-SHA256 | ⭐⭐⭐⭐ | ❌ No (family format) | Stronger Jasypt-style mode shared inside the family |
| `JasyptEncryptor` | PBEWithMD5AndDES | ⭐⭐ | ✅ Yes | Values shared with Java Jasypt |

### Choose the Right Algorithm

```php
<?php

use PHPCrypt\Encryptor;
use PHPCrypt\JasyptEncryptor;
use PHPCrypt\JasyptStrongEncryptor;

// RECOMMENDED: when only PHP/Go/Rust/Node/Python services read the value
$enc = new Encryptor($password);

// When Java Jasypt must read the value (Jasypt's default algorithm)
$enc = new JasyptEncryptor($password);

// Stronger CBC mode shared inside the family. Java Jasypt can NOT read it.
$enc = new JasyptStrongEncryptor($password);
```

**Rule of thumb:** when a Java service reads the same configuration, always use `JasyptEncryptor`.

---

## ☕ Java Jasypt Compatibility

### ⚠️ Important: Compatibility Matrix

```
┌──────────────────────────────────────────────────────────────────────┐
│            ENCRYPT WITH → DECRYPT WITH                               │
├──────────────────────────────────────────────────────────────────────┤
│ Java Jasypt PBEWithMD5AndDES → JasyptEncryptor            ✅ YES     │
│ JasyptEncryptor              → Java Jasypt PBEWithMD5AndDES ✅ YES   │
│ Java Jasypt (any algorithm)  → Encryptor                  ❌ NO      │
│ Encryptor                    → Java Jasypt                ❌ NO      │
│ Java Jasypt AES algorithms   → JasyptStrongEncryptor      ❌ NO      │
│ JasyptStrongEncryptor        → Java Jasypt                ❌ NO      │
│ GoCrypt / RustCrypt / NodeCrypt / PyCrypt, same mode      ✅ YES     │
│   (all three modes, both directions)                                 │
└──────────────────────────────────────────────────────────────────────┘
```

**`JasyptStrongEncryptor` is not Java compatible.** It is the family's own strong format,
`salt ‖ ciphertext` with the IV derived by PBKDF2. Jasypt's `PBEWithHmacSHA256AndAES_256`
stores a random IV in the payload (`salt ‖ iv ‖ ciphertext`), so neither side reads the other.
It does not even fail loudly: CBC has no integrity check, and decrypting a real Jasypt value
with `JasyptStrongEncryptor` returned 16 bytes of garbage followed by the plaintext.

**Which algorithm does your Java side use?** `JasyptEncryptor` matches Jasypt 1.9.3 with
`PBEWithMD5AndDES` and no IV generator, which is what `StandardPBEStringEncryptor` and
`BasicTextEncryptor` do when left alone. `jasypt-spring-boot` 3.0.5 defaults to
`PBEWITHHMACSHA512ANDAES_256` with a random IV instead, and no library in this family reads
that. To share values, the Java side has to use `PBEWithMD5AndDES` with
`org.jasypt.iv.NoIvGenerator` (in `jasypt-spring-boot`: `jasypt.encryptor.algorithm` and
`jasypt.encryptor.iv-generator-classname`). This was tested against the Jasypt library itself,
not inside a Spring Boot application.

### Decrypt Values from Java

```php
<?php

use PHPCrypt\JasyptEncryptor;

// Your Java application.properties has:
// db.password=ENC(xxxFromJavaxxx)

$enc = new JasyptEncryptor($samePasswordAsJava);
$decrypted = $enc->decryptPrefixed('ENC(xxxFromJavaxxx)'); // ✅ Works!
```

### Share Config with Go/Python/Node.js

```php
<?php

use PHPCrypt\JasyptEncryptor;

// Use JasyptEncryptor so all languages can read
$enc = new JasyptEncryptor($sharedPassword);
$encrypted = $enc->encryptWithPrefix('shared_secret');

// This ENC(...) value can be decrypted by:
// - PHP: using JasyptEncryptor
// - Go: using gocrypt.NewJasyptEncryptor
// - Python: using pycrypt.JasyptEncryptor
// - Node.js: using nodecrypt.JasyptEncryptor
// - Java: using Jasypt library
```

### ✅ What has actually been tested

Only the rows below were executed. A format that matches on paper is not a test.

| Counterpart | Mode | Direction | Result |
|-------------|------|-----------|--------|
| GoCrypt v1.0.0, golden vectors | default, `--jasypt`, `--jasypt-strong` | GoCrypt → PHPCrypt, and byte-identical output for a fixed salt | ✅ every CI job |
| GoCrypt v1.0.0 | default, `--jasypt`, `--jasypt-strong` | both | ✅ CI `interop` job |
| RustCrypt v1.0.0 | default, `--jasypt`, `--jasypt-strong` | both | ✅ CI `interop` job |
| NodeCrypt 1.0.1 | default, `--jasypt`, `--jasypt-strong` | both | ✅ CI `interop` job |
| PyCrypt 1.0.1 | default, `--jasypt`, `--jasypt-strong` | both | ✅ CI `interop` job |
| Java Jasypt 1.9.3, `PBEWithMD5AndDES` | `--jasypt` | both | ✅ CI `interop` job |
| Java Jasypt 1.9.3, `PBEWithHmacSHA256AndAES_256` | `--jasypt-strong` | both | ❌ not compatible, by design of the family format |

Each live round trip covers ASCII, punctuation, a 200-character value, non-ASCII text with an
emoji, and a non-ASCII password. The `interop` job runs on Linux with the OpenSSL legacy provider
enabled and fails if any test is skipped. The same tests passed on Windows (PHP 8.5.12,
OpenSSL 3.5.9, JDK 25) on 2026-11-19. Do not use PyCrypt 1.0.0 with the default mode: its values
cannot be read by the other libraries (fixed in PyCrypt 1.0.1).

### 🔑 `JasyptEncryptor` needs the OpenSSL legacy provider

`PBEWithMD5AndDES` uses DES, which OpenSSL 3 only offers through its legacy provider. Without it
`JasyptEncryptor` throws. Point `OPENSSL_CONF` at a file like this before PHP starts:

```ini
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
legacy = legacy_sect
[default_sect]
activate = 1
[legacy_sect]
activate = 1
```

On Windows also set `OPENSSL_MODULES` to the folder that holds `legacy.dll` (the official PHP
builds ship it in `extras\ssl`). `Encryptor` and `JasyptStrongEncryptor` do not need any of this.

---

## 📖 Usage Guide

### Configuration Files

#### .env File

```env
# config.env
DATABASE_HOST=localhost
DATABASE_PASSWORD=ENC(AbCdEf123456...)
API_KEY=ENC(XyZ789...)
```

```php
<?php

use PHPCrypt\ConfigLoader;

$loader = new ConfigLoader($password);
$config = $loader->loadEnvFile('config.env');
echo $config['DATABASE_PASSWORD']; // decrypted value
```

#### JSON File

```php
$config = $loader->loadJson('config.json');
```

#### Set to Environment Variables

```php
$loader->setToEnv('.env');
// Now use getenv()
echo getenv('DATABASE_PASSWORD');
```

### Decrypt Map

```php
$config = [
    'host' => 'localhost',
    'password' => 'ENC(encrypted_value)',
];

$decrypted = $enc->decryptMap($config);
echo $decrypted['password']; // plaintext
```

### Check if Value is Encrypted

```php
<?php

use PHPCrypt\Utils;

if (Utils::isEncrypted($value)) {
    $decrypted = $enc->decryptPrefixed($value);
}
```

---

## 🔧 Framework Integration

### Laravel

```php
// In config/app.php or a service provider
use PHPCrypt\JasyptEncryptor;

$enc = new JasyptEncryptor(env('PHPCRYPT_PASSWORD'));
$dbPassword = $enc->decryptPrefixed(env('DATABASE_PASSWORD'));

// Or create a facade/service
```

### Symfony

```php
// In services.yaml
services:
    PHPCrypt\JasyptEncryptor:
        arguments:
            $password: '%env(PHPCRYPT_PASSWORD)%'
```

---

## 💻 CLI Tool

### Usage

```bash
# Encrypt a value
./vendor/bin/phpcrypt encrypt -p mySecret -v "database_password"
# Output: ENC(base64value...)

# Decrypt a value
./vendor/bin/phpcrypt decrypt -p mySecret -v "ENC(base64value...)"
# Output: database_password

# Encrypt all values in a file
./vendor/bin/phpcrypt encrypt-file -p mySecret -i .env.plain -o .env.encrypted

# Decrypt all values in a file
./vendor/bin/phpcrypt decrypt-file -p mySecret -i .env.encrypted -o .env.plain

# Use Jasypt-compatible algorithm
./vendor/bin/phpcrypt encrypt -p mySecret -v "secret" --jasypt

# Use environment variable for password
export PHPCRYPT_PASSWORD=mySecret
./vendor/bin/phpcrypt encrypt -v "secret_value"
```

---

## ⚙️ Advanced Configuration

### Custom Options

```php
// Encryptor (AES-256-GCM)
$enc = new Encryptor(
    password: $password,
    iterations: 50000,  // default: 10000
    saltSize: 32,       // default: 16
    keySize: 32         // 32 = AES-256 (default), 24 = AES-192, 16 = AES-128
);

// Jasypt Compatible
$enc = new JasyptEncryptor(
    password: $password,
    iterations: 2000    // default: 1000
);

// Jasypt Strong
$enc = new JasyptStrongEncryptor(
    password: $password,
    iterations: 5000,
    saltSize: 32
);
```

---

## 📚 API Reference

### Encryptor

```php
$enc = new Encryptor($password, $iterations, $saltSize, $keySize);

$enc->encrypt($plaintext);           // Returns base64
$enc->encryptWithPrefix($plaintext); // Returns ENC(base64)
$enc->decrypt($base64);
$enc->decryptPrefixed($value);
$enc->decryptAllInString($input);
$enc->decryptMap($config);
```

### JasyptEncryptor

```php
$enc = new JasyptEncryptor($password, $iterations);
// Same methods as Encryptor
```

### JasyptStrongEncryptor

```php
$enc = new JasyptStrongEncryptor($password, $iterations, $saltSize);
// Same methods as Encryptor
```

### ConfigLoader

```php
$loader = new ConfigLoader($password, $iterations);

$loader->loadEnvFile($filepath);
$loader->loadJson($filepath);
$loader->setToEnv($filepath);
```

### Utility Functions

```php
use PHPCrypt\Utils;

Utils::isEncrypted('ENC(abc)');  // true
Utils::isEncrypted('plaintext'); // false
```

---

## 🧪 Testing

```bash
# Install dependencies
composer install

# Run tests
composer test

# Run with coverage
composer test-coverage
```

Tests that need DES are skipped when the OpenSSL legacy provider is not loaded, and the live
cross-language tests are skipped unless you tell them where the other tools are:

```bash
export GOCRYPT_CLI=/path/to/gocrypt-cli       # github.com/farizfadian/gocrypt releases
export RUSTCRYPT_CLI=/path/to/rustcrypt       # github.com/farizfadian/rustcrypt releases
export NODECRYPT_CLI=/path/to/nodecrypt       # npm install -g nodecrypt-jasypt
export PYCRYPT_CLI=/path/to/pycrypt           # pip install pycrypt-jasypt
export JASYPT_JAR=/path/to/jasypt-1.9.3.jar   # org.jasypt:jasypt on Maven Central, needs java on PATH

# Fails instead of skipping when something is missing
vendor/bin/phpunit --fail-on-skipped
```

---

## 📁 Project Structure

```
phpcrypt/
├── src/
│   ├── Encryptor.php          # AES-256-GCM encryption
│   ├── JasyptEncryptor.php    # Jasypt compatibility
│   ├── JasyptStrongEncryptor.php
│   ├── ConfigLoader.php       # Config file loader
│   └── Utils.php              # Utility functions
├── bin/
│   └── phpcrypt               # CLI tool
├── tests/
│   ├── EncryptorTest.php
│   ├── JasyptCompatTest.php
│   ├── UtilsTest.php
│   ├── CliTest.php                    # bin/phpcrypt end to end
│   ├── GoldenVectorTest.php           # GoCrypt golden vectors
│   ├── BackwardCompatibilityTest.php  # values written by PHPCrypt 1.0.0
│   ├── LiveInteropTest.php            # live round trips with the other libraries
│   ├── interop/JasyptTool.java        # drives the real Jasypt jar
│   └── fixtures/                      # gocrypt_vectors.json, phpcrypt_1_0_0_vectors.json
├── composer.json
├── phpunit.xml
├── README.md
└── LICENSE
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Related Projects

- [GoCrypt](https://github.com/farizfadian/gocrypt) - Jasypt-like encryption for Go
- [PyCrypt](https://github.com/farizfadian/pycrypt) - Jasypt-like encryption for Python
- [NodeCrypt](https://github.com/farizfadian/nodecrypt) - Jasypt-like encryption for Node.js
- [RustCrypt](https://github.com/farizfadian/rustcrypt) - Jasypt-like encryption for Rust
- [Jasypt](http://www.jasypt.org/) - Original Java library

---

<p align="center">
  <b>Made with ❤️ from Claude AI for PHP developers who need Jasypt</b>
</p>
