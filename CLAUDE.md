# CLAUDE.md - Complete Development Context for PHPCrypt

> **IMPORTANT**: This file contains ALL context needed for Claude AI to understand and work on PHPCrypt.

---

## 🎯 Project Summary

**PHPCrypt** is a Jasypt-like encryption library for PHP, part of a cross-language encryption family.

```
Owner       : Fariz Fadian (github.com/farizfadian)
Repository  : github.com/farizfadian/phpcrypt
Language    : PHP 8.0+
License     : MIT
Package     : farizfadian/phpcrypt (Packagist)
Dependencies: ext-openssl (built-in)
Created     : December 2024
```

---

## 🔗 Cross-Language Family (ALL SAME ENC() FORMAT!)

```
┌─────────────────────────────────────────────────────────────────┐
│                 Jasypt Encryption Library Family                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   🐹 GoCrypt    github.com/farizfadian/gocrypt     (Go)         │
│   🐍 PyCrypt    github.com/farizfadian/pycrypt     (Python)     │
│   📦 NodeCrypt  github.com/farizfadian/nodecrypt   (Node.js)    │
│   🐘 PHPCrypt   github.com/farizfadian/phpcrypt    (PHP)        │
│   ☕ Jasypt     jasypt.org                         (Java)       │
│                                                                  │
│   ALL USE JasyptEncryptor FOR CROSS-LANGUAGE COMPATIBILITY!    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
phpcrypt/
├── src/
│   ├── Encryptor.php              # AES-256-GCM
│   ├── JasyptEncryptor.php        # PBEWithMD5AndDES
│   ├── JasyptStrongEncryptor.php  # AES-256-CBC
│   ├── ConfigLoader.php           # Load .env, JSON
│   └── Utils.php                  # isEncrypted()
├── bin/
│   └── phpcrypt                   # CLI tool
├── tests/
├── composer.json
├── phpunit.xml
└── README.md
```

---

## 🔐 Three Encryptors

| Class | Algorithm | Java Compatible? |
|-------|-----------|------------------|
| `Encryptor` | AES-256-GCM | ❌ NO |
| `JasyptEncryptor` | PBEWithMD5AndDES | ✅ YES |
| `JasyptStrongEncryptor` | AES-256-CBC | ✅ YES |

---

## 💻 Commands

```bash
# Install
composer install

# Test
composer test

# CLI
./bin/phpcrypt encrypt -p password -v "secret" --jasypt
```

---

## 📝 API Reference

```php
use PHPCrypt\JasyptEncryptor;
use PHPCrypt\ConfigLoader;
use PHPCrypt\Utils;

// Create
$enc = new JasyptEncryptor($password);

// Encrypt/Decrypt
$encrypted = $enc->encryptWithPrefix($plaintext);  // ENC(...)
$plaintext = $enc->decryptPrefixed('ENC(...)');

// Batch
$decryptedMap = $enc->decryptMap($configArray);

// Config
$loader = new ConfigLoader($password);
$config = $loader->loadEnvFile('.env');
```

---

## 🔧 Framework Support

- ✅ Laravel
- ✅ Symfony
- ✅ CodeIgniter
- ✅ Slim
- ✅ Any PHP 8.0+ application

---

<p align="center"><b>Made with ❤️ from Claude AI</b></p>
