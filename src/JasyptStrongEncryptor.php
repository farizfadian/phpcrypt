<?php

declare(strict_types=1);

namespace PHPCrypt;

/**
 * Stronger Jasypt-style encryptor: PBKDF2-HMAC-SHA256 + AES-256-CBC.
 *
 * This is the family's "strong" format, the same as GoCrypt (the reference
 * implementation): base64( salt . ciphertext ), where PBKDF2 derives 48 bytes,
 * the first 32 being the AES-256 key and the last 16 the CBC IV.
 *
 * It is NOT readable by Java Jasypt. Jasypt's own PBEWithHmacSHA256AndAES_256
 * stores a random IV in the payload (salt . iv . ciphertext), so neither side
 * can read the other. When Java must read the value, use JasyptEncryptor.
 *
 * Example:
 * ```php
 * $enc = new JasyptStrongEncryptor('myPassword');
 * $encrypted = $enc->encryptWithPrefix('secret');
 * ```
 *
 * Made with ❤️ from Claude AI for PHP developers who need Jasypt.
 */
class JasyptStrongEncryptor
{
    private const DEFAULT_ITERATIONS = 1000;
    private const DEFAULT_SALT_SIZE = 16;
    private const KEY_SIZE = 32; // AES-256
    private const IV_SIZE = 16;  // AES block size
    private const BLOCK_SIZE = 16;

    private string $password;
    private int $iterations;
    private int $saltSize;

    /**
     * Create a new JasyptStrongEncryptor.
     *
     * @param string $password The encryption password
     * @param int $iterations Key derivation iteration count (default: 1000)
     * @param int $saltSize Salt size in bytes (default: 16)
     */
    public function __construct(
        string $password,
        int $iterations = self::DEFAULT_ITERATIONS,
        int $saltSize = self::DEFAULT_SALT_SIZE
    ) {
        if ($password === '') {
            throw new \InvalidArgumentException('Password cannot be empty');
        }

        $this->password = $password;
        $this->iterations = $iterations;
        $this->saltSize = $saltSize;
    }

    /**
     * Derive key and IV using PBKDF2-HMAC-SHA256.
     *
     * @return array{key: string, iv: string}
     */
    private function deriveKeyAndIv(string $salt): array
    {
        // Derive 48 bytes: 32 for key + 16 for IV
        $derived = hash_pbkdf2('sha256', $this->password, $salt, $this->iterations, self::KEY_SIZE + self::IV_SIZE, true);

        return [
            'key' => substr($derived, 0, self::KEY_SIZE),
            'iv' => substr($derived, self::KEY_SIZE),
        ];
    }

    /**
     * Encrypt using AES-256-CBC with PBKDF2-HMAC-SHA256.
     */
    public function encrypt(string $plaintext): string
    {
        return $this->encryptWithSalt($plaintext, random_bytes($this->saltSize));
    }

    /**
     * Deterministic core of encrypt().
     *
     * @internal Not part of the public API. encrypt() always passes a fresh random
     *           salt; the test suite calls this to reproduce GoCrypt's fixed-salt
     *           vectors byte for byte.
     */
    private function encryptWithSalt(string $plaintext, string $salt): string
    {
        if ($plaintext === '') {
            throw new \InvalidArgumentException('Plaintext cannot be empty');
        }

        // Derive key and IV
        $derived = $this->deriveKeyAndIv($salt);

        // Encrypt with AES-256-CBC
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-cbc',
            $derived['key'],
            OPENSSL_RAW_DATA,
            $derived['iv']
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed');
        }

        // Combine salt + ciphertext
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
     * Decrypt a value in the family strong format (not Java Jasypt's).
     */
    public function decrypt(string $encoded): string
    {
        if ($encoded === '') {
            throw new \InvalidArgumentException('Encoded value cannot be empty');
        }

        $combined = base64_decode($encoded, true);
        if ($combined === false) {
            throw new \InvalidArgumentException('Invalid base64 encoding');
        }

        if (strlen($combined) < $this->saltSize + self::BLOCK_SIZE) {
            throw new \InvalidArgumentException('Invalid data');
        }

        $salt = substr($combined, 0, $this->saltSize);
        $ciphertext = substr($combined, $this->saltSize);

        if (strlen($ciphertext) % self::BLOCK_SIZE !== 0) {
            throw new \InvalidArgumentException('Invalid data');
        }

        // Derive key and IV
        $derived = $this->deriveKeyAndIv($salt);

        // Decrypt
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-cbc',
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
