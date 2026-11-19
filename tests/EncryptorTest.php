<?php

declare(strict_types=1);

namespace PHPCrypt\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
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

    // ════════════════════════════════════════════════════════════════════════
    // Key sizes (as in GoCrypt: 16 = AES-128, 24 = AES-192, 32 = AES-256)
    // ════════════════════════════════════════════════════════════════════════

    /** @return array<string, array{int}> */
    public static function supportedKeySizes(): array
    {
        return ['AES-128' => [16], 'AES-192' => [24], 'AES-256' => [32]];
    }

    #[DataProvider('supportedKeySizes')]
    public function testEncryptDecryptWithKeySize(int $keySize): void
    {
        $enc = new Encryptor('password', 1000, 16, $keySize);

        $this->assertSame('key size test', $enc->decrypt($enc->encrypt('key size test')));
    }

    public function testKeySizeSelectsTheCipher(): void
    {
        // PHPCrypt 1.0.0 always used AES-256 and let OpenSSL zero-pad a shorter
        // key. A 16-byte key must now give AES-128, as in GoCrypt, so a new
        // value must not fit the old layout.
        $encoded = (new Encryptor('password', 1000, 16, 16))->encrypt('hello');

        $raw = (string) base64_decode($encoded, true);
        $key = hash_pbkdf2('sha256', 'password', substr($raw, 0, 16), 1000, 16, true);
        $asOldLayout = openssl_decrypt(
            substr($raw, 28, -16),
            'aes-256-gcm',
            str_pad($key, 32, "\0"),
            OPENSSL_RAW_DATA,
            substr($raw, 16, 12),
            substr($raw, -16)
        );

        $this->assertFalse($asOldLayout);
    }

    public function testUnsupportedKeySizeIsRejectedOnEncrypt(): void
    {
        $enc = new Encryptor('password', 1000, 16, 20);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported key size 20');
        $enc->encrypt('hello');
    }

    public function testTooShortCiphertextIsRejected(): void
    {
        $enc = new Encryptor('password');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('too short');
        $enc->decrypt(base64_encode('short'));
    }

    // ════════════════════════════════════════════════════════════════════════
    // The string "0" is a value, not an empty value (as in GoCrypt)
    // ════════════════════════════════════════════════════════════════════════

    public function testEncryptDecryptZeroString(): void
    {
        $enc = new Encryptor('password');

        $this->assertSame('0', $enc->decrypt($enc->encrypt('0')));
        $this->assertSame('0', $enc->decryptPrefixed($enc->encryptWithPrefix('0')));
    }

    public function testZeroStringPasswordIsAccepted(): void
    {
        $enc = new Encryptor('0');

        $this->assertSame('secret', $enc->decrypt($enc->encrypt('secret')));
    }
}
