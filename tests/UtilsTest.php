<?php

declare(strict_types=1);

namespace PHPCrypt\Tests;

use PHPUnit\Framework\TestCase;
use PHPCrypt\Utils;

/**
 * Lives in its own file: PHPUnit 10 only loads the class named after the file,
 * so these tests never ran while they shared EncryptorTest.php.
 */
class UtilsTest extends TestCase
{
    public function testIsEncryptedWithEncryptedValue(): void
    {
        $this->assertTrue(Utils::isEncrypted('ENC(abc123)'));
    }

    public function testIsEncryptedWithEmptyEnc(): void
    {
        $this->assertTrue(Utils::isEncrypted('ENC()'));
    }

    public function testIsEncryptedWithSpaces(): void
    {
        $this->assertTrue(Utils::isEncrypted('  ENC(value)  '));
    }

    public function testIsEncryptedWithPlaintext(): void
    {
        $this->assertFalse(Utils::isEncrypted('plaintext'));
    }

    public function testIsEncryptedWithMissingClosing(): void
    {
        $this->assertFalse(Utils::isEncrypted('ENC(missing'));
    }

    public function testIsEncryptedWithEmptyString(): void
    {
        $this->assertFalse(Utils::isEncrypted(''));
    }

    public function testIsEncryptedWithNull(): void
    {
        $this->assertFalse(Utils::isEncrypted(null));
    }
}
