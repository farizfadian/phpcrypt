<?php

declare(strict_types=1);

namespace PHPCrypt;

/**
 * Jasypt-compatible encryptor using PBEWithMD5AndDES.
 *
 * This encryptor is compatible with Java Jasypt's default algorithm.
 * Use this when you need to decrypt values encrypted by Java Jasypt
 * or when Go/Python/Node.js applications need to read the same encrypted config.
 *
 * WARNING: This algorithm is considered weak by modern standards.
 * Use only for backward compatibility with existing Jasypt-encrypted values.
 *
 * Example:
 * ```php
 * $enc = new JasyptEncryptor('myPassword');
 *
 * // Decrypt value from Java
 * $decrypted = $enc->decryptPrefixed('ENC(fromJava)');
 *
 * // Encrypt for Java/Go/Python/Node compatibility
 * $encrypted = $enc->encryptWithPrefix('secret');
 * ```
 *
 * Made with ❤️ from Claude AI for PHP developers who need Jasypt.
 */
class JasyptEncryptor
{
    private const DEFAULT_ITERATIONS = 1000;
    private const SALT_SIZE = 8; // DES uses 8-byte salt
    private const BLOCK_SIZE = 8; // DES block size

    private string $password;
    private int $iterations;

    /**
     * Create a new JasyptEncryptor.
     *
     * @param string $password The encryption password
     * @param int $iterations Key derivation iteration count (default: 1000)
     * @throws \InvalidArgumentException If password is empty
     */
    public function __construct(string $password, int $iterations = self::DEFAULT_ITERATIONS)
    {
        if (empty($password)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }

        $this->password = $password;
        $this->iterations = $iterations;
    }

    /**
     * Derive key and IV using PBKDF1 with MD5 (Jasypt's method).
     * This implements the OpenSSL EVP_BytesToKey function used by Jasypt.
     *
     * @return array{key: string, iv: string}
     */
    private function deriveKeyAndIv(string $salt): array
    {
        $data = $this->password . $salt;

        // First iteration
        $result = md5($data, true);

        // Additional iterations
        for ($i = 1; $i < $this->iterations; $i++) {
            $result = md5($result, true);
        }

        // MD5 produces 16 bytes, split into key (8) and IV (8)
        return [
            'key' => substr($result, 0, 8),
            'iv' => substr($result, 8, 8),
        ];
    }

    /**
     * Encrypt plaintext using PBEWithMD5AndDES (Jasypt compatible).
     *
     * @param string $plaintext The text to encrypt
     * @return string Base64-encoded ciphertext
     */
    public function encrypt(string $plaintext): string
    {
        if (empty($plaintext)) {
            throw new \InvalidArgumentException('Plaintext cannot be empty');
        }

        // Generate random salt
        $salt = random_bytes(self::SALT_SIZE);

        // Derive key and IV
        $derived = $this->deriveKeyAndIv($salt);

        // Encrypt with DES-CBC
        $ciphertext = openssl_encrypt(
            $plaintext,
            'des-cbc',
            $derived['key'],
            OPENSSL_RAW_DATA,
            $derived['iv']
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed');
        }

        // Combine salt + ciphertext (Jasypt format)
        $combined = $salt . $ciphertext;

        return base64_encode($combined);
    }

    /**
     * Encrypt and wrap with ENC(...) prefix.
     */
    public function encryptWithPrefix(string $plaintext): string
    {
        $encrypted = $this->encrypt($plaintext);
        return Utils::ENC_PREFIX . $encrypted . Utils::ENC_SUFFIX;
    }

    /**
     * Decrypt Jasypt-encrypted data.
     *
     * @param string $encoded Base64-encoded ciphertext
     * @return string Decrypted plaintext
     */
    public function decrypt(string $encoded): string
    {
        if (empty($encoded)) {
            throw new \InvalidArgumentException('Encoded value cannot be empty');
        }

        $combined = base64_decode($encoded, true);
        if ($combined === false) {
            throw new \InvalidArgumentException('Invalid base64 encoding');
        }

        // Minimum size: 8 (salt) + 8 (at least one block)
        if (strlen($combined) < 16) {
            throw new \InvalidArgumentException('Invalid Jasypt data');
        }

        // Extract salt and ciphertext
        $salt = substr($combined, 0, self::SALT_SIZE);
        $ciphertext = substr($combined, self::SALT_SIZE);

        // Ciphertext must be multiple of block size
        if (strlen($ciphertext) % self::BLOCK_SIZE !== 0) {
            throw new \InvalidArgumentException('Invalid Jasypt data');
        }

        // Derive key and IV
        $derived = $this->deriveKeyAndIv($salt);

        // Decrypt
        $plaintext = openssl_decrypt(
            $ciphertext,
            'des-cbc',
            $derived['key'],
            OPENSSL_RAW_DATA,
            $derived['iv']
        );

        if ($plaintext === false) {
            throw new \InvalidArgumentException('Decryption failed: invalid password or corrupted data');
        }

        return $plaintext;
    }

    /**
     * Decrypt a value with ENC(...) prefix.
     */
    public function decryptPrefixed(string $value): string
    {
        $value = trim($value);

        if (!Utils::isEncrypted($value)) {
            throw new \InvalidArgumentException(
                'Invalid encrypted format, expected ' . Utils::ENC_PREFIX . '...' . Utils::ENC_SUFFIX
            );
        }

        $encrypted = substr($value, strlen(Utils::ENC_PREFIX), -strlen(Utils::ENC_SUFFIX));
        return $this->decrypt($encrypted);
    }

    /**
     * Decrypt all ENC(...) values in a string.
     */
    public function decryptAllInString(string $input): string
    {
        return preg_replace_callback(Utils::ENC_PATTERN, function ($matches) {
            try {
                return $this->decryptPrefixed($matches[0]);
            } catch (\Exception $e) {
                return $matches[0];
            }
        }, $input);
    }

    /**
     * Decrypt all ENC(...) values in an array.
     *
     * @param array<string, string> $config
     * @return array<string, string>
     */
    public function decryptMap(array $config): array
    {
        $result = [];

        foreach ($config as $key => $value) {
            if (Utils::isEncrypted($value)) {
                try {
                    $result[$key] = $this->decryptPrefixed($value);
                } catch (\Exception $e) {
                    $result[$key] = $value;
                }
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }
}
