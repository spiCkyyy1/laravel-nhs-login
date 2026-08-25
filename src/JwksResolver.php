<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Contracts\Cache\Repository as Cache;
use Spickyyy1\NhsLogin\Exceptions\JwksUnavailable;
use Throwable;

/**
 * Fetches and caches NHS login's public signing keys.
 *
 * Cached because an uncached JWKS fetch would add a network round trip to
 * every login; refreshable because a rotation mid-cache would otherwise
 * reject every valid token until the entry expired.
 */
final class JwksResolver
{
    private const ALGORITHM = 'RS512';

    public function __construct(
        private readonly ClientInterface $http,
        private readonly Cache $cache,
        private readonly int $ttl = 3600,
        private readonly int $refreshCooldown = 60,
    ) {}

    /**
     * @return array<string, Key>
     *
     * @throws JwksUnavailable
     */
    public function keys(string $jwksUri): array
    {
        return $this->parse($this->cached($jwksUri), $jwksUri);
    }

    /**
     * Re-fetch the key set, bypassing the cache.
     *
     * Rate limited on purpose. This is reached when a token names a key we do
     * not hold, and that is attacker-controllable — without the cooldown,
     * a stream of tokens carrying invented key IDs would turn into a stream of
     * requests to NHS login with our name on them.
     *
     * @return array<string, Key>
     */
    public function refresh(string $jwksUri): array
    {
        $cooldown = $this->cooldownKey($jwksUri);

        if ($this->cache->get($cooldown) !== null) {
            return $this->keys($jwksUri);
        }

        $this->cache->put($cooldown, true, $this->refreshCooldown);

        $jwks = $this->fetch($jwksUri);

        // Parsed before it is cached. A document that cannot be turned into
        // keys must not be stored, or one bad response from a proxy becomes an
        // outage lasting the whole TTL with the cooldown blocking the retry.
        $keys = $this->parse($jwks, $jwksUri);

        $this->cache->put($this->cacheKey($jwksUri), $jwks, $this->ttl);

        return $keys;
    }

    /**
     * Drop the cached key set entirely, cooldown included.
     */
    public function forget(string $jwksUri): void
    {
        $this->cache->forget($this->cacheKey($jwksUri));
        $this->cache->forget($this->cooldownKey($jwksUri));
    }

    /**
     * @param  array<string, mixed>  $jwks
     * @return array<string, Key>
     *
     * @throws JwksUnavailable
     */
    private function parse(array $jwks, string $jwksUri): array
    {
        try {
            // RS512 is supplied as the default algorithm because "alg" is
            // optional per RFC 7517, and parseKeySet refuses a key without one.
            // A key set NHS login is entitled to publish should not be an
            // outage here.
            $keys = JWK::parseKeySet($jwks, self::ALGORITHM);
        } catch (Throwable $e) {
            throw JwksUnavailable::malformed($jwksUri, $e);
        }

        return $keys !== [] ? $keys : throw JwksUnavailable::noKeys($jwksUri);
    }

    /**
     * @return array<string, mixed>
     */
    private function cached(string $jwksUri): array
    {
        /** @var array<string, mixed> $jwks */
        $jwks = $this->cache->remember(
            $this->cacheKey($jwksUri),
            $this->ttl,
            fn (): array => $this->fetch($jwksUri),
        );

        return $jwks;
    }

    /**
     * Fetch and sanity check, so nothing unusable ever reaches the cache.
     *
     * @return array<string, mixed>
     *
     * @throws JwksUnavailable
     */
    private function fetch(string $jwksUri): array
    {
        try {
            $response = $this->http->request('GET', $jwksUri, [
                'headers' => ['Accept' => 'application/json'],
            ]);
        } catch (GuzzleException $e) {
            throw JwksUnavailable::unreachable($jwksUri, $e);
        }

        try {
            $decoded = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            // A captive portal or an error page served with a 200 lands here.
            throw JwksUnavailable::malformed($jwksUri, $e);
        }

        if (! is_array($decoded) || ! isset($decoded['keys']) || ! is_array($decoded['keys'])) {
            throw JwksUnavailable::malformed($jwksUri);
        }

        if ($decoded['keys'] === []) {
            throw JwksUnavailable::noKeys($jwksUri);
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    private function cacheKey(string $jwksUri): string
    {
        return 'nhs-login.jwks.'.sha1($jwksUri);
    }

    private function cooldownKey(string $jwksUri): string
    {
        return 'nhs-login.jwks.cooldown.'.sha1($jwksUri);
    }
}
