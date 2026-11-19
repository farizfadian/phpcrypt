<?php

declare(strict_types=1);

namespace PHPCrypt\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use PHPCrypt\Encryptor;
use PHPCrypt\JasyptEncryptor;
use PHPCrypt\JasyptStrongEncryptor;

/**
 * Live round trips against other implementations, in both directions.
 *
 * The counterparts are located through environment variables. A test whose
 * counterpart is absent is skipped with a message naming the variable:
 *
 *   GOCRYPT_CLI    gocrypt-cli (github.com/farizfadian/gocrypt releases)
 *   RUSTCRYPT_CLI  rustcrypt   (github.com/farizfadian/rustcrypt releases)
 *   NODECRYPT_CLI  nodecrypt   (npm: nodecrypt-jasypt, 1.0.1 or newer)
 *   PYCRYPT_CLI    pycrypt     (PyPI: pycrypt-jasypt, 1.0.1 or newer)
 *   JASYPT_JAR     jasypt-1.9.3.jar (org.jasypt:jasypt on Maven Central);
 *                  needs `java` (JDK 11+) on PATH, or JAVA_BIN pointing to it
 *
 * A *_CLI variable holds the path of an executable. For a tool that needs an
 * interpreter it may hold a JSON list instead, for example
 * ["node", "--openssl-legacy-provider", "/path/to/nodecrypt/dist/cli.js"].
 *
 * The CI "interop" job sets all five on Linux, enables the OpenSSL legacy
 * provider and runs with --fail-on-skipped, so nothing here can pass by
 * being skipped.
 */
#[Group('interop')]
class LiveInteropTest extends TestCase
{
    use DesAvailability;

    private const PASSWORD = 'phpcrypt-interop-2026';
    private const NON_ASCII_PASSWORD = 'pässwörd-日本語-🔑';

    /** PHPCrypt mode => flag; every family command-line tool uses the layout of bin/phpcrypt. */
    private const MODES = [
        'default' => null,
        'jasypt' => '--jasypt',
        'jasypt-strong' => '--jasypt-strong',
    ];

    private const CLI_TOOLS = [
        'GoCrypt' => 'GOCRYPT_CLI',
        'RustCrypt' => 'RUSTCRYPT_CLI',
        'NodeCrypt' => 'NODECRYPT_CLI',
        'PyCrypt' => 'PYCRYPT_CLI',
    ];

    /** @return array<string, array{string, string}> label => [plaintext, password] */
    private static function cases(): array
    {
        return [
            'ASCII' => ['hello', self::PASSWORD],
            'punctuation' => ['p@$$w0rd!#%^&*()_+=[]{}|;:\'",.<>/?`~ \\ end', self::PASSWORD],
            '200 characters' => [str_repeat('0123456789', 20), self::PASSWORD],
            'non-ASCII text with emoji' => ['Selamat pagi, こんにちは 🦀', self::PASSWORD],
            'non-ASCII password' => ['hello', self::NON_ASCII_PASSWORD],
        ];
    }

    // ════════════════════════════════════════════════════════════════════════
    // GoCrypt, RustCrypt, NodeCrypt and PyCrypt: all three modes
    // ════════════════════════════════════════════════════════════════════════

    /** @return iterable<string, array{string, string, string, string, string}> */
    public static function cliCases(): iterable
    {
        foreach (self::CLI_TOOLS as $name => $envVar) {
            foreach (array_keys(self::MODES) as $mode) {
                foreach (self::cases() as $label => [$plaintext, $password]) {
                    yield "$name, $mode, $label" => [$name, $envVar, $mode, $plaintext, $password];
                }
            }
        }
    }

    #[DataProvider('cliCases')]
    public function testPhpCryptDecryptsCounterpartOutput(
        string $name,
        string $envVar,
        string $mode,
        string $plaintext,
        string $password
    ): void {
        $cli = $this->requireTool($name, $envVar);
        $this->requireMode($mode);

        $wrapped = $this->runCommand(array_merge($cli, ['encrypt', '-p', $password, '-v', $plaintext], self::flag($mode)));

        $this->assertStringStartsWith('ENC(', $wrapped, "$name output");
        $this->assertSame($plaintext, self::encryptor($mode, $password)->decryptPrefixed($wrapped));
    }

    #[DataProvider('cliCases')]
    public function testCounterpartDecryptsPhpCryptOutput(
        string $name,
        string $envVar,
        string $mode,
        string $plaintext,
        string $password
    ): void {
        $cli = $this->requireTool($name, $envVar);
        $this->requireMode($mode);

        $wrapped = self::encryptor($mode, $password)->encryptWithPrefix($plaintext);
        $decrypted = $this->runCommand(array_merge($cli, ['decrypt', '-p', $password, '-v', $wrapped], self::flag($mode)));

        $this->assertSame($plaintext, $decrypted, "$name must decrypt PHPCrypt output");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Real Java Jasypt: PBEWithMD5AndDES (the --jasypt mode)
    // ════════════════════════════════════════════════════════════════════════

    /** @return iterable<string, array{string, string}> */
    public static function jasyptCases(): iterable
    {
        foreach (self::cases() as $label => [$plaintext, $password]) {
            yield $label => [$plaintext, $password];
        }
    }

    #[DataProvider('jasyptCases')]
    public function testPhpCryptDecryptsRealJasyptOutput(string $plaintext, string $password): void
    {
        $jar = $this->requireJasypt();
        $this->skipIfDesNotAvailable();

        // The Jasypt API returns bare base64; the ENC(...) wrapper belongs to the config layer.
        $encoded = $this->jasypt($jar, 'encrypt', 'PBEWithMD5AndDES', $password, $plaintext);

        $this->assertSame($plaintext, (new JasyptEncryptor($password))->decrypt($encoded));
    }

    #[DataProvider('jasyptCases')]
    public function testRealJasyptDecryptsPhpCryptOutput(string $plaintext, string $password): void
    {
        $jar = $this->requireJasypt();
        $this->skipIfDesNotAvailable();

        $encoded = (new JasyptEncryptor($password))->encrypt($plaintext);

        $this->assertSame($plaintext, $this->jasypt($jar, 'decrypt', 'PBEWithMD5AndDES', $password, $encoded));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Real Java Jasypt vs the family "strong" format: NOT compatible
    // ════════════════════════════════════════════════════════════════════════

    public function testRealJasyptCannotReadTheStrongFormat(): void
    {
        $jar = $this->requireJasypt();

        $encoded = (new JasyptStrongEncryptor(self::PASSWORD))->encrypt('hello');

        try {
            $result = $this->jasypt($jar, 'decrypt', 'PBEWithHmacSHA256AndAES_256', self::PASSWORD, $encoded, false);
        } catch (\RuntimeException $e) {
            $this->addToAssertionCount(1);

            return;
        }

        $this->assertNotSame('hello', $result, 'If this ever passes, the strong mode became Java compatible: update the docs');
    }

    public function testStrongFormatCannotReadRealJasypt(): void
    {
        $jar = $this->requireJasypt();

        // Jasypt writes salt . iv . ciphertext with a random IV. The family format
        // has no IV in the payload, so the IV block is decrypted as if it were data.
        $encoded = $this->jasypt($jar, 'encrypt', 'PBEWithHmacSHA256AndAES_256', self::PASSWORD, 'hello');
        $this->assertSame(48, strlen((string) base64_decode($encoded, true)), 'salt(16) + iv(16) + one block');

        try {
            $result = (new JasyptStrongEncryptor(self::PASSWORD))->decrypt($encoded);
        } catch (\InvalidArgumentException $e) {
            $this->addToAssertionCount(1);

            return;
        }

        $this->assertNotSame('hello', $result, 'If this ever passes, the strong mode became Java compatible: update the docs');
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    private static function encryptor(string $mode, string $password): Encryptor|JasyptEncryptor|JasyptStrongEncryptor
    {
        return match ($mode) {
            'default' => new Encryptor($password),
            'jasypt' => new JasyptEncryptor($password),
            'jasypt-strong' => new JasyptStrongEncryptor($password),
        };
    }

    /** @return list<string> */
    private static function flag(string $mode): array
    {
        return self::MODES[$mode] === null ? [] : [self::MODES[$mode]];
    }

    private function requireMode(string $mode): void
    {
        if ($mode === 'jasypt') {
            $this->skipIfDesNotAvailable();
        }
    }

    /** @return list<string> the command that starts the tool */
    private function requireTool(string $name, string $envVar): array
    {
        $value = getenv($envVar);
        if ($value === false || $value === '') {
            $this->markTestSkipped("$envVar is not set: live round trips against $name were not run");
        }

        if (str_starts_with($value, '[')) {
            $command = json_decode($value, true);
            $this->assertIsArray($command, "$envVar looks like a JSON list but does not decode");
            $this->assertNotEmpty($command, "$envVar is an empty list");

            return array_map('strval', array_values($command));
        }

        $this->assertFileExists($value, "$envVar must point to the $name command-line tool");

        return [$value];
    }

    private function requireJasypt(): string
    {
        $jar = getenv('JASYPT_JAR');
        if ($jar === false || $jar === '') {
            $this->markTestSkipped('JASYPT_JAR is not set: live round trips against Java Jasypt were not run');
        }

        $this->assertFileExists($jar, 'JASYPT_JAR must point to the Jasypt jar');

        return $jar;
    }

    private function jasypt(
        string $jar,
        string $operation,
        string $algorithm,
        string $password,
        string $value,
        bool $mustSucceed = true
    ): string {
        $java = getenv('JAVA_BIN');
        $command = [
            $java === false || $java === '' ? 'java' : $java,
            '-cp',
            $jar,
            __DIR__ . DIRECTORY_SEPARATOR . 'interop' . DIRECTORY_SEPARATOR . 'JasyptTool.java',
        ];

        return $this->runCommand($command, "$operation\n$algorithm\n$password\n$value\n", $mustSucceed);
    }

    /**
     * Runs a command without a shell and returns its stdout, minus the final newline.
     *
     * @param list<string> $command
     * @throws \RuntimeException when $mustSucceed is false and the command fails
     */
    private function runCommand(array $command, ?string $stdin = null, bool $mustSucceed = true): string
    {
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $this->assertNotFalse($process, 'could not start ' . basename($command[0]));

        if ($stdin !== null) {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);
        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        if ($exitCode !== 0) {
            $message = sprintf('%s exited with %d: %s', basename($command[0]), $exitCode, trim($stderr));
            if (!$mustSucceed) {
                throw new \RuntimeException($message);
            }
            $this->fail($message);
        }

        return rtrim($stdout, "\r\n");
    }
}
