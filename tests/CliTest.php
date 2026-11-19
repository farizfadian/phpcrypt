<?php

declare(strict_types=1);

namespace PHPCrypt\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end tests for bin/phpcrypt, run as a separate PHP process.
 */
class CliTest extends TestCase
{
    use DesAvailability;

    /** @var list<string> */
    private array $tempFiles = [];

    protected function setUp(): void
    {
        // A password in the developer's environment must not leak into these tests.
        putenv('PHPCRYPT_PASSWORD');
    }

    protected function tearDown(): void
    {
        putenv('PHPCRYPT_PASSWORD');
        foreach ($this->tempFiles as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        $this->tempFiles = [];
    }

    /** @return array<string, array{list<string>}> */
    public static function modes(): array
    {
        return [
            'default' => [[]],
            'jasypt' => [['--jasypt']],
            'jasypt-strong' => [['--jasypt-strong']],
        ];
    }

    /** @param list<string> $flag */
    #[DataProvider('modes')]
    public function testEncryptThenDecrypt(array $flag): void
    {
        if ($flag === ['--jasypt']) {
            $this->skipIfDesNotAvailable();
        }

        [$exitCode, $encrypted] = $this->phpcrypt(array_merge(['encrypt', '-p', 'cliPassword', '-v', 'cli secret'], $flag));
        $this->assertSame(0, $exitCode);
        $this->assertStringStartsWith('ENC(', $encrypted);

        [$exitCode, $decrypted] = $this->phpcrypt(array_merge(['decrypt', '-p', 'cliPassword', '-v', $encrypted], $flag));
        $this->assertSame(0, $exitCode);
        $this->assertSame('cli secret', $decrypted);
    }

    public function testNoPrefixGivesBareBase64(): void
    {
        [$exitCode, $encrypted] = $this->phpcrypt(['encrypt', '-p', 'cliPassword', '-v', 'cli secret', '--no-prefix']);
        $this->assertSame(0, $exitCode);
        $this->assertStringStartsNotWith('ENC(', $encrypted);

        [, $decrypted] = $this->phpcrypt(['decrypt', '-p', 'cliPassword', '-v', $encrypted]);
        $this->assertSame('cli secret', $decrypted);
    }

    public function testZeroIsAValue(): void
    {
        [$exitCode, $encrypted, $stderr] = $this->phpcrypt(['encrypt', '-p', 'cliPassword', '-v', '0']);
        $this->assertSame(0, $exitCode, $stderr);

        [, $decrypted] = $this->phpcrypt(['decrypt', '-p', 'cliPassword', '-v', $encrypted]);
        $this->assertSame('0', $decrypted);
    }

    public function testZeroIsAPassword(): void
    {
        [$exitCode, $encrypted, $stderr] = $this->phpcrypt(['encrypt', '-p', '0', '-v', 'cli secret']);
        $this->assertSame(0, $exitCode, $stderr);

        [, $decrypted] = $this->phpcrypt(['decrypt', '-p', '0', '-v', $encrypted]);
        $this->assertSame('cli secret', $decrypted);
    }

    public function testPasswordFromEnvironment(): void
    {
        putenv('PHPCRYPT_PASSWORD=envPassword');

        [$exitCode, $encrypted, $stderr] = $this->phpcrypt(['encrypt', '-v', 'cli secret']);
        $this->assertSame(0, $exitCode, $stderr);

        [, $decrypted] = $this->phpcrypt(['decrypt', '-p', 'envPassword', '-v', $encrypted]);
        $this->assertSame('cli secret', $decrypted);
    }

    public function testMissingPasswordFails(): void
    {
        [$exitCode, $stdout, $stderr] = $this->phpcrypt(['encrypt', '-v', 'cli secret']);

        $this->assertSame(1, $exitCode);
        $this->assertSame('', $stdout);
        $this->assertStringContainsString('password is required', $stderr);
    }

    public function testEncryptFileThenDecryptFile(): void
    {
        $plain = $this->tempFile("# comment\nHOST=localhost\nDEBUG=0\nEMPTY=\nTOKEN=\"quoted value\"\n");
        $encrypted = $this->tempFile('');
        $decrypted = $this->tempFile('');

        [$exitCode, , $stderr] = $this->phpcrypt(['encrypt-file', '-p', 'cliPassword', '-i', $plain, '-o', $encrypted]);
        $this->assertSame(0, $exitCode, $stderr);

        $lines = explode("\n", (string) file_get_contents($encrypted));
        $this->assertSame('# comment', $lines[0]);
        $this->assertStringStartsWith('HOST=ENC(', $lines[1]);
        $this->assertStringStartsWith('DEBUG=ENC(', $lines[2], 'the value "0" is encrypted like any other, as gocrypt-cli does');
        $this->assertSame('EMPTY=', $lines[3]);
        $this->assertStringStartsWith('TOKEN=ENC(', $lines[4]);

        [$exitCode, , $stderr] = $this->phpcrypt(['decrypt-file', '-p', 'cliPassword', '-i', $encrypted, '-o', $decrypted]);
        $this->assertSame(0, $exitCode, $stderr);
        $this->assertSame(
            "# comment\nHOST=localhost\nDEBUG=0\nEMPTY=\nTOKEN=quoted value\n",
            file_get_contents($decrypted)
        );
    }

    public function testVersion(): void
    {
        [$exitCode, $stdout] = $this->phpcrypt(['version']);

        $this->assertSame(0, $exitCode);
        $this->assertMatchesRegularExpression('/^phpcrypt \d+\.\d+\.\d+$/', $stdout);
    }

    /**
     * @param list<string> $args
     * @return array{int, string, string} exit code, stdout without the final newline, stderr
     */
    private function phpcrypt(array $args): array
    {
        $command = array_merge([PHP_BINARY, dirname(__DIR__) . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'phpcrypt'], $args);

        // No environment array: the child inherits ours, including OPENSSL_CONF.
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $this->assertNotFalse($process, 'could not start bin/phpcrypt');

        fclose($pipes[0]);
        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($process), rtrim($stdout, "\r\n"), $stderr];
    }

    private function tempFile(string $content): string
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'phpcrypt-test-');
        file_put_contents($file, $content);
        $this->tempFiles[] = $file;

        return $file;
    }
}
