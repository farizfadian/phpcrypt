<?php

declare(strict_types=1);

namespace PHPCrypt\Tests;

use PHPUnit\Framework\TestCase;
use PHPCrypt\Encryptor;
use PHPCrypt\Utils;

class EncryptorTest extends TestCase
{
    public function testEncryptDecryptSimple(): void
    {
        $enc = new Encryptor('mySecretPassword');

        $plaintext = 'hello';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertNotEquals($plaintext, $encrypted);
    }

    public function testEncryptDecryptWithSpaces(): void
    {
        $enc = new Encryptor('password');

        $plaintext = 'hello world with spaces';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptDecryptSpecialChars(): void
    {
        $enc = new Encryptor('password');

        $plaintext = 'p@$$w0rd!#$%^&*()';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptDecryptUnicode(): void
    {
        $enc = new Encryptor('password');

        $plaintext = 'こんにちは世界 🔐';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptDecryptJson(): void
    {
        $enc = new Encryptor('password');

        $plaintext = '{"username":"admin","password":"secret123"}';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptDecryptConnectionString(): void
    {
        $enc = new Encryptor('password');

        $plaintext = 'postgresql://user:pass@localhost:5432/dbname?sslmode=disable';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptWithPrefix(): void
    {
        $enc = new Encryptor('password');

        $plaintext = 'mysecret';
        $encrypted = $enc->encryptWithPrefix($plaintext);

        $this->assertTrue(str_starts_with($encrypted, 'ENC('));
        $this->assertTrue(str_ends_with($encrypted, ')'));
        $this->assertTrue(Utils::isEncrypted($encrypted));

        $decrypted = $enc->decryptPrefixed($encrypted);
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testWrongPasswordThrows(): void
    {
        $enc1 = new Encryptor('correctPassword');
        $enc2 = new Encryptor('wrongPassword');

        $encrypted = $enc1->encrypt('secret');

        $this->expectException(\InvalidArgumentException::class);
        $enc2->decrypt($encrypted);
    }

    public function testEmptyPasswordThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Encryptor('');
    }

    public function testEmptyPlaintextThrows(): void
    {
        $enc = new Encryptor('password');

        $this->expectException(\InvalidArgumentException::class);
        $enc->encrypt('');
    }

    public function testDifferentEncryptionsProduceDifferentResults(): void
    {
        $enc = new Encryptor('password');
        $plaintext = 'same value';

        $encrypted1 = $enc->encrypt($plaintext);
        $encrypted2 = $enc->encrypt($plaintext);

        $this->assertNotEquals($encrypted1, $encrypted2);

        // But both decrypt to same value
        $this->assertEquals($plaintext, $enc->decrypt($encrypted1));
        $this->assertEquals($plaintext, $enc->decrypt($encrypted2));
    }

    public function testDecryptAllInString(): void
    {
        $enc = new Encryptor('password');

        $enc1 = $enc->encryptWithPrefix('user123');
        $enc2 = $enc->encryptWithPrefix('pass456');

        $input = "username=$enc1\npassword=$enc2";
        $result = $enc->decryptAllInString($input);

        $this->assertStringContainsString('username=user123', $result);
        $this->assertStringContainsString('password=pass456', $result);
    }

    public function testDecryptMap(): void
    {
        $enc = new Encryptor('password');

        $encryptedPass = $enc->encryptWithPrefix('secretPassword');
        $encryptedKey = $enc->encryptWithPrefix('apiKey123');

        $config = [
            'host' => 'localhost',
            'port' => '5432',
            'password' => $encryptedPass,
            'api_key' => $encryptedKey,
        ];

        $decrypted = $enc->decryptMap($config);

        $this->assertEquals('localhost', $decrypted['host']);
        $this->assertEquals('secretPassword', $decrypted['password']);
        $this->assertEquals('apiKey123', $decrypted['api_key']);
    }

    public function testCustomIterations(): void
    {
        $enc = new Encryptor('password', 20000);

        $plaintext = 'test';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }
}

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
