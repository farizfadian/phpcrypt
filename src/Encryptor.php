<?php

declare(strict_types=1);

namespace PHPCrypt;

/**
 * AES-256-GCM Encryptor - Recommended for new projects.
 *
 * This encryptor uses AES-256-GCM which provides authenticated encryption,
 * meaning it can detect if the ciphertext has been tampered with.
 *
 * Example:
 * ```php
 * $enc = new Encryptor('myPassword');
 * $encrypted = $enc->encryptWithPrefix('secret');
 * $decrypted = $enc->decryptPrefixed($encrypted);
 * ```
 *
 * Note: This encryptor is NOT compatible with Java Jasypt.
 * For Jasypt compatibility, use JasyptEncryptor.
 *
 * Made with ❤️ from Claude AI for PHP developers who need Jasypt.
 */
class Encryptor
{
    private const DEFAULT_ITERATIONS = 10000;
    private const DEFAULT_SALT_SIZE = 16;
    private const DEFAULT_KEY_SIZE = 32; // AES-256
    private const IV_SIZE = 12; // GCM standard
    private const TAG_SIZE = 16;

    private string $password;
    private int $iterations;
    private int $saltSize;
    private int $keySize;

    /**
     * Create a new Encryptor.
     *
     * @param string $password The encryption password
     * @param int $iterations PBKDF2 iteration count (default: 10000)
     * @param int $saltSize Salt size in bytes (default: 16)
     * @param int $keySize Key size in bytes (default: 32 for AES-256)
     * @throws \InvalidArgumentException If password is empty
     */
    public function __construct(
        string $password,
        int $iterations = self::DEFAULT_ITERATIONS,
        int $saltSize = self::DEFAULT_SALT_SIZE,
        int $keySize = self::DEFAULT_KEY_SIZE
    ) {
        if (empty($password)) {
            throw new \InvalidArgumentException('Password cannot be empty');
        }

        $this->password = $password;
        $this->iterations = $iterations;
        $this->saltSize = $saltSize;
        $this->keySize = $keySize;
    }

    /**
     * Derive key from password using PBKDF2-HMAC-SHA256.
     */
    private function deriveKey(string $salt): string
    {
        return hash_pbkdf2('sha256', $this->password, $salt, $this->iterations, $this->keySize, true);
    }

    /**
     * Encrypt plaintext and return base64-encoded ciphertext.
     *
     * @param string $plaintext The text to encrypt
     * @return string Base64-encoded ciphertext
     * @throws \InvalidArgumentException If plaintext is empty
     */
    public function encrypt(string $plaintext): string
    {
        if (empty($plaintext)) {
            throw new \InvalidArgumentException('Plaintext cannot be empty');
        }

        // Generate random salt and IV
        $salt = random_bytes($this->saltSize);
        $iv = random_bytes(self::IV_SIZE);

        // Derive key
        $key = $this->deriveKey($salt);

        // Encrypt with AES-256-GCM
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_SIZE
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed');
        }

        // Combine: salt + iv + ciphertext + tag
        $combined = $salt . $iv . $ciphertext . $tag;

        return base64_encode($combined);
    }

    /**
     * Encrypt and wrap with ENC(...) prefix.
     *
     * @param string $plaintext The text to encrypt
     * @return string Encrypted value in format: ENC(base64...)
     */
    public function encryptWithPrefix(string $plaintext): string
    {
        $encrypted = $this->encrypt($plaintext);
        return Utils::ENC_PREFIX . $encrypted . Utils::ENC_SUFFIX;
    }

    /**
     * Decrypt base64-encoded ciphertext.
     *
     * @param string $encoded Base64-encoded ciphertext
     * @return string Decrypted plaintext
     * @throws \InvalidArgumentException If decryption fails
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

        // Extract components
        $salt = substr($combined, 0, $this->saltSize);
        $iv = substr($combined, $this->saltSize, self::IV_SIZE);
        $tag = substr($combined, -self::TAG_SIZE);
        $ciphertext = substr($combined, $this->saltSize + self::IV_SIZE, -self::TAG_SIZE);

        // Derive key
        $key = $this->deriveKey($salt);

        // Decrypt
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            throw new \InvalidArgumentException('Decryption failed: invalid password or corrupted data');
        }

        return $plaintext;
    }

    /**
     * Decrypt a value with ENC(...) prefix.
     *
     * @param string $value Encrypted value in format ENC(base64...)
     * @return string Decrypted plaintext
     * @throws \InvalidArgumentException If format is invalid or decryption fails
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
     *
     * @param string $input String containing ENC(...) values
     * @return string String with all ENC(...) values decrypted
     */
    public function decryptAllInString(string $input): string
    {
        return preg_replace_callback(Utils::ENC_PATTERN, function ($matches) {
            try {
                return $this->decryptPrefixed($matches[0]);
            } catch (\Exception $e) {
                return $matches[0]; // Keep original on error
            }
        }, $input);
    }

    /**
     * Decrypt all ENC(...) values in an array.
     *
     * @param array<string, string> $config Array with potentially encrypted values
     * @return array<string, string> Array with all ENC(...) values decrypted
     */
    public function decryptMap(array $config): array
    {
        $result = [];

        foreach ($config as $key => $value) {
            if (Utils::isEncrypted($value)) {
                try {
                    $result[$key] = $this->decryptPrefixed($value);
                } catch (\Exception $e) {
                    $result[$key] = $value; // Keep original on error
                }
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }
}
