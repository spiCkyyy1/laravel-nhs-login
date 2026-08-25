<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Support;

use Spickyyy1\NhsLogin\Exceptions\NhsLoginConfigurationException;

/**
 * Resolves the signing key from either inline PEM contents or a file path.
 *
 * Inline suits platforms where secrets arrive as environment variables; a
 * path suits mounted secrets. Never log or echo the result.
 */
final class PrivateKey
{
    /**
     * @throws NhsLoginConfigurationException
     */
    public static function resolve(?string $contents, ?string $path): string
    {
        if ($contents !== null && trim($contents) !== '') {
            // Env vars cannot hold real newlines, so accept the escaped form.
            return str_replace('\n', "\n", $contents);
        }

        if ($path === null || trim($path) === '') {
            throw NhsLoginConfigurationException::missingPrivateKey();
        }

        if (! is_readable($path)) {
            throw NhsLoginConfigurationException::unreadablePrivateKey($path);
        }

        $pem = file_get_contents($path);

        return $pem === false
            ? throw NhsLoginConfigurationException::unreadablePrivateKey($path)
            : $pem;
    }

    /**
     * The public half, in PEM form.
     *
     * Only the mock issuer needs this — it verifies client assertions the way
     * NHS login would, using the key you registered with them.
     *
     * @throws NhsLoginConfigurationException
     */
    public static function publicKey(string $privateKey, ?string $passphrase = null): string
    {
        $key = openssl_pkey_get_private($privateKey, $passphrase);

        if ($key === false) {
            throw NhsLoginConfigurationException::unusablePrivateKey();
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || ! isset($details['key'])) {
            throw NhsLoginConfigurationException::unusablePrivateKey();
        }

        return (string) $details['key'];
    }
}
