<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Support;

use Spickyyy1\NhsLogin\Exceptions\NhsLoginConfigurationException;

/**
 * Resolves every NHS login endpoint from a single issuer.
 *
 * NHS login publishes a standard discovery document, but the paths have been
 * stable and fetching it on every request would add a network round trip to
 * each login. The paths below mirror
 * {issuer}/.well-known/openid-configuration exactly.
 */
final readonly class Environment
{
    private function __construct(public string $issuer) {}

    /**
     * @param  array<string, string>  $issuers
     *
     * @throws NhsLoginConfigurationException
     */
    public static function resolve(string $name, array $issuers, ?string $override = null): self
    {
        if ($override !== null && $override !== '') {
            return new self(rtrim($override, '/'));
        }

        if (! isset($issuers[$name])) {
            throw NhsLoginConfigurationException::unknownEnvironment($name, array_keys($issuers));
        }

        return new self(rtrim($issuers[$name], '/'));
    }

    public function authorizeEndpoint(): string
    {
        return $this->issuer.'/authorize';
    }

    public function tokenEndpoint(): string
    {
        return $this->issuer.'/token';
    }

    public function userInfoEndpoint(): string
    {
        return $this->issuer.'/userinfo';
    }

    public function jwksUri(): string
    {
        return $this->issuer.'/.well-known/jwks.json';
    }
}
