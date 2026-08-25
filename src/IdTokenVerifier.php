<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Spickyyy1\NhsLogin\Exceptions\InvalidIdToken;
use Spickyyy1\NhsLogin\Support\Environment;
use Throwable;

/**
 * Verifies the ID token returned by NHS login.
 *
 * The access token alone says nothing about who signed in — the ID token is
 * the assertion of identity, and an unverified one is worthless. Signature,
 * issuer, audience and nonce are all checked; any failure abandons the session.
 */
final class IdTokenVerifier
{
    public function __construct(
        private readonly JwksResolver $jwks,
        private readonly string $clientId,
        private readonly int $leeway = 30,
    ) {}

    /**
     * @return array<string, mixed> the verified claims
     *
     * @throws InvalidIdToken
     */
    public function verify(?string $idToken, Environment $environment, ?string $expectedNonce): array
    {
        if ($idToken === null || $idToken === '') {
            throw InvalidIdToken::missing();
        }

        $claims = $this->decode($idToken, $this->keysFor($idToken, $environment));

        $this->assertIssuer($claims, $environment);
        $this->assertAudience($claims);
        $this->assertExpiry($claims);
        $this->assertNonce($claims, $expectedNonce);

        return $claims;
    }

    /**
     * @param  array<string, Key>  $keys
     * @return array<string, mixed>
     *
     * @throws InvalidIdToken
     */
    private function decode(string $idToken, array $keys): array
    {
        // Leeway is a global on the library, so it is restored afterwards
        // rather than left as a side effect on anything else decoding JWTs.
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->leeway;

        try {
            return (array) JWT::decode($idToken, $keys);
        } catch (Throwable $e) {
            throw InvalidIdToken::unverifiable($e);
        } finally {
            JWT::$leeway = $previousLeeway;
        }
    }

    /**
     * Resolve the signing keys, re-fetching once if the token names a key we
     * do not hold.
     *
     * NHS login rotates without warning. Trusting a stale cache would reject
     * every login until it expired; the resolver rate limits the re-fetch so
     * a forged key ID cannot turn this into a stream of requests.
     *
     * @return array<string, Key>
     */
    private function keysFor(string $idToken, Environment $environment): array
    {
        $keys = $this->jwks->keys($environment->jwksUri());
        $kid = self::keyId($idToken);

        if ($kid === null || array_key_exists($kid, $keys)) {
            return $keys;
        }

        return $this->jwks->refresh($environment->jwksUri());
    }

    /**
     * Read the key ID from the unverified header.
     *
     * Safe despite being unverified: the value is only ever used to choose
     * which public key to check the signature against, and a wrong guess
     * fails that check.
     */
    private static function keyId(string $idToken): ?string
    {
        $segments = explode('.', $idToken);

        if (count($segments) !== 3) {
            return null;
        }

        $decoded = base64_decode(strtr($segments[0], '-_', '+/'), strict: false);

        if ($decoded === false) {
            return null;
        }

        $header = json_decode($decoded, true);

        return is_array($header) && isset($header['kid']) && is_string($header['kid'])
            ? $header['kid']
            : null;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertIssuer(array $claims, Environment $environment): void
    {
        $issuer = isset($claims['iss']) ? rtrim((string) $claims['iss'], '/') : '';

        if ($issuer !== $environment->issuer) {
            throw InvalidIdToken::issuerMismatch($environment->issuer, $issuer);
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertAudience(array $claims): void
    {
        $audience = $claims['aud'] ?? null;
        $audiences = is_array($audience) ? $audience : [$audience];

        if (! in_array($this->clientId, array_map('strval', $audiences), strict: true)) {
            throw InvalidIdToken::audienceMismatch($this->clientId);
        }

        // With more than one audience, being named is not enough: OIDC requires
        // azp to say which client the token was actually minted for.
        if (count($audiences) > 1 && ($claims['azp'] ?? null) !== $this->clientId) {
            throw InvalidIdToken::authorizedPartyMismatch($this->clientId);
        }
    }

    /**
     * Require an expiry rather than merely honouring one.
     *
     * JWT::decode only enforces exp when the claim is present, so a token
     * without it would verify for ever. The single-use nonce already blocks
     * replay; this closes the gap rather than relying on that alone.
     *
     * @param  array<string, mixed>  $claims
     */
    private function assertExpiry(array $claims): void
    {
        if (! isset($claims['exp'])) {
            throw InvalidIdToken::missingExpiry();
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertNonce(array $claims, ?string $expectedNonce): void
    {
        if ($expectedNonce === null || $expectedNonce === '') {
            throw InvalidIdToken::missingNonce();
        }

        $nonce = isset($claims['nonce']) ? (string) $claims['nonce'] : '';

        if (! hash_equals($expectedNonce, $nonce)) {
            throw InvalidIdToken::nonceMismatch();
        }
    }
}
