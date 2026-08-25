<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin;

use Firebase\JWT\JWT;
use Illuminate\Support\Str;
use OpenSSLAsymmetricKey;
use Spickyyy1\NhsLogin\Exceptions\NhsLoginConfigurationException;

/**
 * Builds the signed JWT that authenticates this client to NHS login.
 *
 * NHS login supports no other client authentication method: there is no client
 * secret to post. Each token request carries a short-lived assertion signed
 * with the private key whose public half sits on our JWKS endpoint.
 */
final class ClientAssertion
{
    public const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    private const ALGORITHM = 'RS512';

    public function __construct(
        private readonly string $clientId,
        private readonly string $privateKey,
        private readonly ?string $passphrase = null,
        private readonly ?string $keyId = null,
        private readonly int $ttl = 300,
    ) {}

    /**
     * @throws NhsLoginConfigurationException
     */
    public function create(string $audience): string
    {
        $issuedAt = time();

        $claims = [
            // NHS login requires sub and iss to both be the client ID, and the
            // audience to be the token endpoint of the environment in use.
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'aud' => $audience,
            'jti' => (string) Str::uuid(),
            'iat' => $issuedAt,
            'exp' => $issuedAt + $this->ttl,
        ];

        // Passed as the key id rather than in a header array: JWT::encode sets
        // the kid header from this argument and would overwrite a duplicate.
        // An empty configured value means "no kid", not an empty one.
        return JWT::encode($claims, $this->key(), self::ALGORITHM, $this->keyId ?: null);
    }

    /**
     * @throws NhsLoginConfigurationException
     */
    private function key(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_private($this->privateKey, $this->passphrase);

        if ($key === false) {
            throw NhsLoginConfigurationException::unusablePrivateKey();
        }

        return $key;
    }
}
