<?php

declare(strict_types=1);

namespace PHPCrypt;

/**
 * Configuration file loader with automatic decryption.
 *
 * Supports .env, JSON, and PHP array files.
 *
 * Example:
 * ```php
 * $loader = new ConfigLoader('myPassword');
 * $config = $loader->loadEnvFile('.env');
 * echo $config['DATABASE_PASSWORD']; // decrypted value
 *
 * // Load and set as environment variables
 * $loader->setToEnv('.env');
 * echo getenv('DATABASE_PASSWORD');
 * ```
 *
 * Made with ❤️ from Claude AI for PHP developers who need Jasypt.
 */
class ConfigLoader
{
    private Encryptor $encryptor;

    /**
     * Create a new ConfigLoader.
     *
     * @param string $password The encryption password
     * @param int $iterations PBKDF2 iteration count
     */
    public function __construct(string $password, int $iterations = 10000)
    {
        $this->encryptor = new Encryptor($password, $iterations);
    }

    /**
     * Load and decrypt a .env file.
     *
     * @param string $filepath Path to the .env file
     * @return array<string, string> Key-value pairs with decrypted values
     */
    public function loadEnvFile(string $filepath): array
    {
        if (!file_exists($filepath)) {
            throw new \InvalidArgumentException("File not found: $filepath");
        }

        $content = file_get_contents($filepath);
        $config = [];

        foreach (explode("\n", $content) as $line) {
            $line = trim($line);

            // Skip empty lines and comments
            if (empty($line) || str_starts_with($line, '#')) {
                continue;
            }

            // Split by first =
            $pos = strpos($line, '=');
            if ($pos === false) {
                continue;
            }

            $key = trim(substr($line, 0, $pos));
            $value = trim(substr($line, $pos + 1));

            // Remove surrounding quotes
            if ((str_starts_with($value, '"') && str_ends_with($value, '"')) ||
                (str_starts_with($value, "'") && str_ends_with($value, "'"))) {
                $value = substr($value, 1, -1);
            }

            // Decrypt if encrypted
            if (Utils::isEncrypted($value)) {
                try {
                    $value = $this->encryptor->decryptPrefixed($value);
                } catch (\Exception $e) {
                    // Keep original on error
                }
            }

            $config[$key] = $value;
        }

        return $config;
    }

    /**
     * Load and decrypt a JSON configuration file.
     *
     * @param string $filepath Path to the JSON file
     * @return array<string, mixed> Decoded JSON with all ENC(...) values decrypted
     */
    public function loadJson(string $filepath): array
    {
        if (!file_exists($filepath)) {
            throw new \InvalidArgumentException("File not found: $filepath");
        }

        $content = file_get_contents($filepath);
        $config = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid JSON: ' . json_last_error_msg());
        }

        return $this->decryptRecursive($config);
    }

    /**
     * Recursively decrypt all ENC(...) values in an array.
     *
     * @param mixed $data
     * @return mixed
     */
    private function decryptRecursive(mixed $data): mixed
    {
        if (is_string($data)) {
            if (Utils::isEncrypted($data)) {
                try {
                    return $this->encryptor->decryptPrefixed($data);
                } catch (\Exception $e) {
                    return $data;
                }
            }
            return $data;
        }

        if (is_array($data)) {
            $result = [];
            foreach ($data as $key => $value) {
                $result[$key] = $this->decryptRecursive($value);
            }
            return $result;
        }

        return $data;
    }

    /**
     * Load an env file and set values as environment variables.
     *
     * @param string $filepath Path to the .env file
     */
    public function setToEnv(string $filepath): void
    {
        $config = $this->loadEnvFile($filepath);

        foreach ($config as $key => $value) {
            putenv("$key=$value");
            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
        }
    }
}
