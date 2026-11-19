<?php

declare(strict_types=1);

namespace PHPCrypt\Tests;

/**
 * JasyptEncryptor needs DES-CBC, which OpenSSL 3 only offers through its
 * legacy provider. Tests that need it skip, visibly, where it is not loaded.
 *
 * A skipped test proves nothing: the CI "interop" job enables the provider and
 * runs with --fail-on-skipped, so DES is exercised for real on Linux.
 */
trait DesAvailability
{
    private function skipIfDesNotAvailable(): void
    {
        if (!in_array('des-cbc', openssl_get_cipher_methods(), true)) {
            $this->markTestSkipped('DES-CBC not available (OpenSSL legacy provider not loaded)');
        }

        // Also check that it actually works (some systems list it but fail)
        $result = @openssl_encrypt('test', 'des-cbc', '12345678', OPENSSL_RAW_DATA, '12345678');
        if ($result === false) {
            $this->markTestSkipped('DES-CBC listed but not functional (OpenSSL legacy provider not loaded)');
        }
    }
}
