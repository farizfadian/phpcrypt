<?php

declare(strict_types=1);

namespace PHPCrypt\Tests;

use PHPUnit\Framework\TestCase;
use PHPCrypt\JasyptEncryptor;
use PHPCrypt\JasyptStrongEncryptor;
use PHPCrypt\Utils;

class JasyptCompatTest extends TestCase
{
    /**
     * Check if DES-CBC is available (requires OpenSSL legacy provider on 3.0+).
     */
    private function skipIfDesNotAvailable(): void
    {
        $ciphers = openssl_get_cipher_methods();
        if (!in_array('des-cbc', $ciphers, true)) {
            $this->markTestSkipped('DES-CBC not available (OpenSSL legacy provider not loaded)');
        }

        // Also check that it actually works (some systems list it but fail)
        $result = @openssl_encrypt('test', 'des-cbc', '12345678', OPENSSL_RAW_DATA, '12345678');
        if ($result === false) {
            $this->markTestSkipped('DES-CBC listed but not functional (OpenSSL legacy provider not loaded)');
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // JasyptEncryptor Tests
    // ════════════════════════════════════════════════════════════════════════

    public function testJasyptEncryptDecryptSimple(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('mySecretPassword');

        $plaintext = 'hello';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptEncryptDecryptWithSpaces(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('password');

        $plaintext = 'hello world';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptEncryptDecryptSpecialChars(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('password');

        $plaintext = 'p@$$w0rd!#$%';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptEncryptDecryptUnicode(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('password');

        $plaintext = 'こんにちは';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptEncryptDecryptConnectionString(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('password');

        $plaintext = 'jdbc:mysql://localhost:3306/mydb';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptEncryptWithPrefix(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('password');

        $plaintext = 'myDatabasePassword';
        $encrypted = $enc->encryptWithPrefix($plaintext);

        $this->assertTrue(Utils::isEncrypted($encrypted));

        $decrypted = $enc->decryptPrefixed($encrypted);
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptWrongPasswordThrows(): void
    {
        $this->skipIfDesNotAvailable();
        $enc1 = new JasyptEncryptor('correctPassword');
        $enc2 = new JasyptEncryptor('wrongPassword');

        $encrypted = $enc1->encrypt('secret');

        $this->expectException(\InvalidArgumentException::class);
        $enc2->decrypt($encrypted);
    }

    public function testJasyptDecryptMap(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('mapPassword');

        $encPass = $enc->encryptWithPrefix('dbPassword123');
        $encKey = $enc->encryptWithPrefix('apiKey456');

        $config = [
            'host' => 'localhost',
            'port' => '3306',
            'password' => $encPass,
            'api_key' => $encKey,
        ];

        $decrypted = $enc->decryptMap($config);

        $this->assertEquals('localhost', $decrypted['host']);
        $this->assertEquals('dbPassword123', $decrypted['password']);
        $this->assertEquals('apiKey456', $decrypted['api_key']);
    }

    public function testJasyptDecryptAllInString(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('stringPassword');

        $enc1 = $enc->encryptWithPrefix('user123');
        $enc2 = $enc->encryptWithPrefix('pass456');

        $input = "username=$enc1\npassword=$enc2";
        $result = $enc->decryptAllInString($input);

        $this->assertStringContainsString('username=user123', $result);
        $this->assertStringContainsString('password=pass456', $result);
    }

    public function testJasyptCustomIterations(): void
    {
        $this->skipIfDesNotAvailable();
        $enc = new JasyptEncryptor('password', 2000);

        $plaintext = 'test value';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    // ════════════════════════════════════════════════════════════════════════
    // JasyptStrongEncryptor Tests
    // ════════════════════════════════════════════════════════════════════════

    public function testJasyptStrongEncryptDecryptSimple(): void
    {
        $enc = new JasyptStrongEncryptor('mySecretPassword');

        $plaintext = 'hello';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptStrongEncryptDecryptWithSpaces(): void
    {
        $enc = new JasyptStrongEncryptor('password');

        $plaintext = 'hello world';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptStrongEncryptDecryptSpecialChars(): void
    {
        $enc = new JasyptStrongEncryptor('password');

        $plaintext = 'p@$$w0rd!#$%';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptStrongEncryptDecryptUnicode(): void
    {
        $enc = new JasyptStrongEncryptor('password');

        $plaintext = 'こんにちは世界';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptStrongEncryptDecryptLongText(): void
    {
        $enc = new JasyptStrongEncryptor('password');

        $plaintext = 'This is a much longer text for testing AES-256 encryption.';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptStrongEncryptWithPrefix(): void
    {
        $enc = new JasyptStrongEncryptor('strongPassword');

        $plaintext = 'sensitiveData';
        $encrypted = $enc->encryptWithPrefix($plaintext);

        $this->assertTrue(Utils::isEncrypted($encrypted));

        $decrypted = $enc->decryptPrefixed($encrypted);
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testJasyptStrongCustomOptions(): void
    {
        $enc = new JasyptStrongEncryptor('password', 5000, 32);

        $plaintext = 'test';
        $encrypted = $enc->encrypt($plaintext);
        $decrypted = $enc->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }
}
