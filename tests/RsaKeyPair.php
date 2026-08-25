<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;

/**
 * A throwaway RSA key pair generated at run time.
 *
 * Generated rather than committed so the repository never contains anything
 * that looks like a real signing key.
 */
final class RsaKeyPair
{
    private static ?self $shared = null;

    private function __construct(
        private readonly OpenSSLAsymmetricKey $key,
        private readonly string $privateKeyPem,
        public readonly string $kid,
    ) {}

    public static function shared(): self
    {
        return self::$shared ??= self::generate('test-kid');
    }

    public static function generate(string $kid): self
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($key, $pem);

        return new self($key, $pem, $kid);
    }

    public function privateKey(): string
    {
        return $this->privateKeyPem;
    }

    /**
     * The public half in JWKS form, as NHS login would publish it.
     *
     * @return array{keys: list<array<string, string>>}
     */
    public function jwks(): array
    {
        return self::jwksFor($this);
    }

    /**
     * A key set holding several keys, as NHS login publishes mid-rotation.
     *
     * @return array{keys: list<array<string, string>>}
     */
    public static function jwksFor(self ...$pairs): array
    {
        return ['keys' => array_map(static fn (self $pair): array => $pair->jwk(), $pairs)];
    }

    /**
     * @return array<string, string>
     */
    public function jwk(): array
    {
        $details = openssl_pkey_get_details($this->key);

        return [
            'kty' => 'RSA',
            'alg' => 'RS512',
            'use' => 'sig',
            'kid' => $this->kid,
            'n' => self::base64Url($details['rsa']['n']),
            'e' => self::base64Url($details['rsa']['e']),
        ];
    }

    /**
     * Sign claims the way NHS login would.
     *
     * @param  array<string, mixed>  $claims
     */
    public function signIdToken(array $claims): string
    {
        return JWT::encode($claims, $this->key, 'RS512', $this->kid);
    }

    private static function base64Url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
