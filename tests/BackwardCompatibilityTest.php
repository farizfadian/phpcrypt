<?php

declare(strict_types=1);

namespace PHPCrypt\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PHPCrypt\Encryptor;
use PHPCrypt\JasyptEncryptor;
use PHPCrypt\JasyptStrongEncryptor;

/**
 * Every value PHPCrypt 1.0.0 wrote must still decrypt.
 *
 * tests/fixtures/phpcrypt_1_0_0_vectors.json was recorded with the unmodified
 * 1.0.0 code. It matters most for Encryptor with a key size other than 32:
 * 1.0.0 always used AES-256-GCM and OpenSSL zero-padded a shorter key (or cut
 * a longer one), which no other family member can read. Later versions write
 * the family format for 16 and 24 bytes, and must keep reading the old one.
 */
class BackwardCompatibilityTest extends TestCase
{
    use DesAvailability;

    /** @return array<string, mixed> */
    private static function fixture(): array
    {
        static $fixture = null;

        return $fixture ??= json_decode(
            (string) file_get_contents(__DIR__ . '/fixtures/phpcrypt_1_0_0_vectors.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
    }

    public function testFixtureWasWrittenByPhpCrypt100(): void
    {
        $fixture = self::fixture();

        $this->assertSame('1.0.0', $fixture['phpcrypt_version']);
        $this->assertSame(40, strlen($fixture['phpcrypt_commit']));

        $keySizes = [];
        foreach ($fixture['vectors'] as $vector) {
            if ($vector['class'] === 'Encryptor') {
                $keySizes[$vector['key_size']] = true;
            }
        }
        ksort($keySizes);

        // 32 is the default; 16 and 24 are the documented alternatives; 20 and
        // 64 stand for the sizes 1.0.0 accepted without complaint.
        $this->assertSame([16, 20, 24, 32, 64], array_keys($keySizes));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function vectors(): iterable
    {
        foreach (self::fixture()['vectors'] as $i => $vector) {
            $config = $vector['class'];
            if (isset($vector['key_size'])) {
                $config .= ' key_size=' . $vector['key_size'];
            }

            yield sprintf('#%d %s: %s', $i, $config, $vector['plaintext']) => [$vector];
        }
    }

    /** @param array<string, mixed> $vector */
    #[DataProvider('vectors')]
    public function testDecryptsValueWrittenByPhpCrypt100(array $vector): void
    {
        $password = self::fixture()['password'];

        if ($vector['class'] === 'JasyptEncryptor') {
            $this->skipIfDesNotAvailable();
        }

        $encryptor = match ($vector['class']) {
            'Encryptor' => new Encryptor($password, $vector['iterations'], $vector['salt_size'], $vector['key_size']),
            'JasyptEncryptor' => new JasyptEncryptor($password, $vector['iterations']),
            'JasyptStrongEncryptor' => new JasyptStrongEncryptor($password, $vector['iterations'], $vector['salt_size']),
        };

        $this->assertSame($vector['plaintext'], $encryptor->decrypt($vector['encoded']));
    }
}
