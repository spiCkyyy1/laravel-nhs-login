<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Testing;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Support\Str;
use OpenSSLAsymmetricKey;
use Spickyyy1\NhsLogin\ClientAssertion;
use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\Support\Environment;
use Throwable;

/**
 * A local stand-in for NHS login.
 *
 * NHS login has no self-service sandbox: you fill in a form and wait a day for
 * sandpit credentials. This mints its own key pair and plays the other half of
 * the protocol so the flow can be exercised end to end before then.
 *
 * It verifies the client assertion against the public half of the application's
 * own configured signing key, so a key that is misconfigured here is a key that
 * would have been rejected by NHS login too. That is the point: a mock that
 * accepts anything only proves the redirect works.
 */
final class MockIssuer
{
    public const KEY_ID = 'nhs-login-mock-key';

    private const CACHE_PREFIX = 'nhs-login.mock.';

    private const ALGORITHM = 'RS512';

    public function __construct(
        private readonly Cache $cache,
        private readonly Environment $environment,
        private readonly string $clientId,
        private readonly string $clientPublicKey,
        private readonly int $codeTtl = 300,
        private readonly int $tokenTtl = 3600,
    ) {}

    public function issuer(): string
    {
        return $this->environment->issuer;
    }

    /**
     * The key set, in the shape NHS login publishes it.
     *
     * @return array{keys: list<array<string, string>>}
     */
    public function jwks(): array
    {
        $details = openssl_pkey_get_details($this->signingKey());

        return [
            'keys' => [[
                'kty' => 'RSA',
                'alg' => self::ALGORITHM,
                'use' => 'sig',
                'kid' => self::KEY_ID,
                'n' => self::base64Url($details['rsa']['n']),
                'e' => self::base64Url($details['rsa']['e']),
            ]],
        ];
    }

    /**
     * The subset of the discovery document that matters to a client.
     *
     * @return array<string, mixed>
     */
    public function discovery(): array
    {
        return [
            'issuer' => $this->issuer(),
            'authorization_endpoint' => $this->environment->authorizeEndpoint(),
            'token_endpoint' => $this->environment->tokenEndpoint(),
            'userinfo_endpoint' => $this->environment->userInfoEndpoint(),
            'jwks_uri' => $this->environment->jwksUri(),
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => [self::ALGORITHM],
            'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
        ];
    }

    /**
     * Check the client assertion exactly as NHS login would.
     *
     * @throws MockIssuerRejection
     */
    public function verifyClientAssertion(?string $assertion, ?string $type): void
    {
        if ($type !== ClientAssertion::TYPE) {
            throw MockIssuerRejection::invalidClient('Missing or unexpected client_assertion_type.');
        }

        if ($assertion === null || $assertion === '') {
            throw MockIssuerRejection::invalidClient('No client_assertion was posted.');
        }

        try {
            $claims = (array) JWT::decode($assertion, new Key($this->clientPublicKey, self::ALGORITHM));
        } catch (Throwable $e) {
            throw MockIssuerRejection::invalidClient(
                'The client assertion did not verify against your configured key: '.$e->getMessage(),
            );
        }

        foreach (['iss' => $this->clientId, 'sub' => $this->clientId] as $claim => $expected) {
            if (($claims[$claim] ?? null) !== $expected) {
                throw MockIssuerRejection::invalidClient("The assertion's {$claim} must be the client ID.");
            }
        }

        $audience = $claims['aud'] ?? null;
        $audiences = is_array($audience) ? $audience : [$audience];

        if (! in_array($this->environment->tokenEndpoint(), array_map('strval', $audiences), strict: true)) {
            throw MockIssuerRejection::invalidClient(
                "The assertion's aud must be the token endpoint [{$this->environment->tokenEndpoint()}].",
            );
        }
    }

    /**
     * @param  array<string, mixed>  $grant
     */
    public function issueCode(array $grant): string
    {
        $code = Str::random(48);

        $this->cache->put(self::CACHE_PREFIX.'code.'.$code, $grant, $this->codeTtl);

        return $code;
    }

    /**
     * Authorisation codes are single use, here as at NHS login.
     *
     * @return array<string, mixed>|null
     */
    public function claimCode(string $code): ?array
    {
        /** @var array<string, mixed>|null $grant */
        $grant = $this->cache->pull(self::CACHE_PREFIX.'code.'.$code);

        return $grant;
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed> the token response
     */
    public function issueTokens(array $claims, ?string $nonce, string $scope): array
    {
        $accessToken = Str::random(64);
        $issuedAt = time();

        $idToken = array_filter([
            'iss' => $this->issuer(),
            'aud' => $this->clientId,
            'sub' => $claims['sub'] ?? null,
            'iat' => $issuedAt,
            'exp' => $issuedAt + 300,
            'auth_time' => $issuedAt,
            'jti' => (string) Str::uuid(),
            'nonce' => $nonce,
        ], static fn (mixed $value): bool => $value !== null);

        $this->cache->put(self::CACHE_PREFIX.'token.'.$accessToken, $claims, $this->tokenTtl);

        return [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $this->tokenTtl,
            'scope' => $scope,
            'id_token' => $this->sign($idToken + $claims),
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    public function userInfo(string $accessToken): ?array
    {
        /** @var array<string, mixed>|null $claims */
        $claims = $this->cache->get(self::CACHE_PREFIX.'token.'.$accessToken);

        return $claims;
    }

    /**
     * The claims NHS login would return for a user at the given level.
     *
     * @param  array<string, string>  $overrides
     * @return array<string, mixed>
     */
    public function claimsFor(IdentityProofingLevel $level, string $vector, array $overrides = []): array
    {
        $claims = [
            'sub' => $overrides['sub'] ?? 'mock-'.Str::lower(Str::random(16)),
            'vot' => $vector,
            'vtm' => $this->issuer().'/trustmark',
            'identity_proofing_level' => $level->value,
            'email' => $overrides['email'] ?? 'mock.user@example.test',
            'email_verified' => true,
            'phone_number' => $overrides['phone_number'] ?? '07700900000',
            'phone_number_verified' => true,
        ];

        // P0 is authenticated but not identified: no PDS match, so no NHS
        // number and no verified name or date of birth.
        if ($level->isVerified()) {
            $claims += [
                'nhs_number' => $overrides['nhs_number'] ?? '9912003888',
                'birthdate' => $overrides['birthdate'] ?? '1980-04-01',
                'family_name' => $overrides['family_name'] ?? 'Khan',
                'given_name' => $overrides['given_name'] ?? 'Aisha',
            ];
        }

        return $claims;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function sign(array $claims): string
    {
        return JWT::encode($claims, $this->signingKey(), self::ALGORITHM, self::KEY_ID, ['kid' => self::KEY_ID]);
    }

    /**
     * Generated once and cached, so the key set stays stable across the
     * requests that make up a single login.
     */
    private function signingKey(): OpenSSLAsymmetricKey
    {
        $pem = $this->cache->rememberForever(self::CACHE_PREFIX.'signing-key', static function (): string {
            $key = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            if ($key === false || ! openssl_pkey_export($key, $exported)) {
                throw MockIssuerRejection::serverError('The mock issuer could not generate a signing key.');
            }

            return (string) $exported;
        });

        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            // Only reachable if the cached value was corrupted or truncated.
            $this->cache->forget(self::CACHE_PREFIX.'signing-key');

            throw MockIssuerRejection::serverError('The mock signing key could not be loaded. Try again.');
        }

        return $key;
    }

    private static function base64Url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
