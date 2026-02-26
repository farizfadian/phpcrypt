<?php

declare(strict_types=1);

namespace PHPCrypt;

/**
 * Utility functions and constants for PHPCrypt.
 */
class Utils
{
    /** Prefix for encrypted values */
    public const ENC_PREFIX = 'ENC(';

    /** Suffix for encrypted values */
    public const ENC_SUFFIX = ')';

    /** Regex pattern to match ENC(...) values */
    public const ENC_PATTERN = '/ENC\(([^)]+)\)/';

    /**
     * Check if a value is in ENC(...) format.
     *
     * @param string|null $value The value to check
     * @return bool True if value is in ENC(...) format
     *
     * Example:
     * ```php
     * Utils::isEncrypted('ENC(abc123)'); // true
     * Utils::isEncrypted('plaintext');   // false
     * ```
     */
    public static function isEncrypted(?string $value): bool
    {
        if (empty($value)) {
            return false;
        }

        $trimmed = trim($value);
        return str_starts_with($trimmed, self::ENC_PREFIX) && str_ends_with($trimmed, self::ENC_SUFFIX);
    }
}
