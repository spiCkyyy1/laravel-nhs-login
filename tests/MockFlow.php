<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

use Spickyyy1\NhsLogin\ClientAssertion;
use Spickyyy1\NhsLogin\Support\Environment;

/**
 * Drives the mounted mock issuer's endpoints.
 *
 * A class rather than the global functions these started as: every suite loads
 * into one process, so a duplicated helper name is a fatal error rather than a
 * test failure, and names like approve() and exchange() are exactly the ones
 * that collide.
 */
final class MockFlow
{
    public const PREFIX = '/nhs-login-mock';

    public const CLIENT_ID = 'test-client';

    public const CALLBACK = 'http://localhost/auth/nhs/callback';

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    public static function authorizeQuery(array $overrides = []): array
    {
        return array_merge([
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::CALLBACK,
            'response_type' => 'code',
            'scope' => 'openid profile',
            'state' => 'st4te',
            'nonce' => 'test-nonce',
            'vtr' => json_encode(['P9.Cp.Cd', 'P9.Cm']),
        ], $overrides);
    }

    /**
     * Complete the picker form and pull the code out of the redirect.
     *
     * @param  array<string, mixed>  $form
     */
    public static function approve(array $form = []): ?string
    {
        $response = test()->post(self::PREFIX.'/authorize', array_merge([
            'action' => 'approve',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::CALLBACK,
            'state' => 'st4te',
            'nonce' => 'test-nonce',
            'scope' => 'openid profile',
            'vector' => 'P9.Cp.Cd',
        ], $form));

        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        return isset($query['code']) ? (string) $query['code'] : null;
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    public static function exchange(string $code, array $overrides = []): array
    {
        /** @var Environment $environment */
        $environment = app(Environment::class);

        /** @var ClientAssertion $assertion */
        $assertion = app(ClientAssertion::class);

        return test()->post(self::PREFIX.'/token', array_merge([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::CALLBACK,
            'client_id' => self::CLIENT_ID,
            'client_assertion_type' => ClientAssertion::TYPE,
            'client_assertion' => $assertion->create($environment->tokenEndpoint()),
        ], $overrides))->json();
    }
}
