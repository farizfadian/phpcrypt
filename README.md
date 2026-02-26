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
- ✅ **Java Jasypt compatibility** - Decrypt values encrypted by Java
- ✅ **Multiple algorithms** - From legacy Jasypt to modern AES-256-GCM
- ✅ **Laravel/Symfony ready** - Easy integration with PHP frameworks
- ✅ **CLI tool included** - Encrypt/decrypt from command line
- ✅ **Cross-platform** - Works with GoCrypt, PyCrypt, NodeCrypt, and Java Jasypt

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

| Encryptor | Algorithm | Security | Use Case |
|-----------|-----------|----------|----------|
| `Encryptor` | AES-256-GCM | ⭐⭐⭐⭐⭐ | **Recommended** for new projects |
| `JasyptStrongEncryptor` | PBEWithHmacSHA256AndAES_256 | ⭐⭐⭐⭐ | Jasypt strong compatibility |
| `JasyptEncryptor` | PBEWithMD5AndDES | ⭐⭐ | Legacy Jasypt compatibility |

### Choose the Right Algorithm

```php
<?php

use PHPCrypt\Encryptor;
use PHPCrypt\JasyptEncryptor;
use PHPCrypt\JasyptStrongEncryptor;

// RECOMMENDED: For new PHP projects
$enc = new Encryptor($password);

// For compatibility with Java Jasypt (default algorithm)
$enc = new JasyptEncryptor($password);

// For compatibility with Java Jasypt (strong encryption)
$enc = new JasyptStrongEncryptor($password);
```

---

## ☕ Java Jasypt Compatibility

### ⚠️ Important: Compatibility Matrix

```
┌─────────────────────────────────────────────────────────────────┐
│            ENCRYPT WITH → DECRYPT WITH                          │
├─────────────────────────────────────────────────────────────────┤
│ Java Jasypt (default)  → JasyptEncryptor        ✅ YES          │
│ Java Jasypt (strong)   → JasyptStrongEncryptor  ✅ YES          │
│ Java Jasypt (default)  → Encryptor              ❌ NO           │
│ Encryptor              → Java Jasypt            ❌ NO           │
│ JasyptEncryptor        → Java Jasypt            ✅ YES          │
│ GoCrypt JasyptEnc      → JasyptEncryptor        ✅ YES          │
│ PyCrypt JasyptEnc      → JasyptEncryptor        ✅ YES          │
│ NodeCrypt JasyptEnc    → JasyptEncryptor        ✅ YES          │
└─────────────────────────────────────────────────────────────────┘
```

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
    keySize: 32         // 32 = AES-256
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
│   └── JasyptCompatTest.php
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
- [Jasypt](http://www.jasypt.org/) - Original Java library

---

<p align="center">
  <b>Made with ❤️ from Claude AI for PHP developers who need Jasypt</b>
</p>
