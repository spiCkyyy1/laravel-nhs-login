<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Response;
use Spickyyy1\NhsLogin\Exceptions\InvalidIdToken;
use Spickyyy1\NhsLogin\Exceptions\TokenRequestFailed;
use Spickyyy1\NhsLogin\Support\NhsLoginToken;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;
use Spickyyy1\NhsLogin\Tests\RsaKeyPair;

/**
 * refreshToken() authenticates the same way as every other call to the token
 * endpoint — private_key_jwt, never the client_secret Socialite posts by
 * default — and, when NHS login sends a new ID token back, verifies it the
 * same way the original login's was.
 */
it('authenticates the refresh grant with a signed assertion and never a client secret', function () {
    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
            'scope' => 'openid profile',
        ])),
    ]);

    $factory->provider->refreshToken('old-refresh-token');

    $fields = $factory->lastRequestBody();

    expect($fields)->not->toHaveKey('client_secret')
        ->and($fields['grant_type'])->toBe('refresh_token')
        ->and($fields['refresh_token'])->toBe('old-refresh-token')
        ->and($fields['client_assertion_type'])->not->toBeEmpty()
        ->and($fields['client_assertion'])->not->toBeEmpty();
});

it('returns a token carrying what NHS login sent back', function () {
    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
            'scope' => 'openid profile',
        ])),
    ]);

    $token = $factory->provider->refreshToken('old-refresh-token');

    expect($token)->toBeInstanceOf(NhsLoginToken::class)
        ->and($token->token)->toBe('new-access-token')
        ->and($token->refreshToken)->toBe('new-refresh-token')
        ->and($token->expiresIn)->toBe(3600)
        ->and($token->approvedScopes)->toBe(['openid', 'profile'])
        ->and($token->idTokenClaims)->toBeNull();
});

it('does not choke on an empty scope', function () {
    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
        ])),
    ]);

    expect($factory->provider->refreshToken('old-refresh-token')->approvedScopes)->toBe([]);
});

it('keeps the spent refresh token when NHS login does not send a new one', function () {
    // Not every response rotates it; the caller should not lose the ability
    // to refresh again just because this one did not.
    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'new-access-token',
            'expires_in' => 3600,
            'scope' => 'openid',
        ])),
    ]);

    expect($factory->provider->refreshToken('still-good-refresh-token')->refreshToken)
        ->toBe('still-good-refresh-token');
});

it('verifies a new ID token when NHS login sends one back', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims());

    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'id_token' => $idToken,
        ])),
    ]);

    $token = $factory->provider->refreshToken('old-refresh-token', 'nhs-sub-123');

    expect($token->idTokenClaims)->not->toBeNull()
        ->and($token->idTokenClaims['sub'])->toBe('nhs-sub-123');
});

it('refuses a refreshed ID token naming a different subject than expected', function () {
    // The refresh has to prove it is still the same person, not a token for
    // whoever happened to be issued one — see IdTokenVerifier::verifyRefreshed().
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims(['sub' => 'someone-else']));

    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'id_token' => $idToken,
        ])),
    ]);

    expect(fn () => $factory->provider->refreshToken('old-refresh-token', 'nhs-sub-123'))
        ->toThrow(InvalidIdToken::class);
});

it('does not check the subject when the caller does not supply one to check it against', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims(['sub' => 'anyone-at-all']));

    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'id_token' => $idToken,
        ])),
    ]);

    expect($factory->provider->refreshToken('old-refresh-token')->idTokenClaims['sub'])
        ->toBe('anyone-at-all');
});

it('still refuses a refreshed ID token with the wrong issuer or audience', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims(['aud' => 'someone-elses-client-id']));

    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'new-access-token',
            'expires_in' => 3600,
            'id_token' => $idToken,
        ])),
    ]);

    expect(fn () => $factory->provider->refreshToken('old-refresh-token'))
        ->toThrow(InvalidIdToken::class);
});

it('surfaces the reason NHS login rejected a refresh request', function () {
    $factory = ProviderFactory::make([
        new Response(400, ['Content-Type' => 'application/json'], json_encode([
            'error' => 'invalid_grant',
            'error_description' => 'Refresh token has expired',
        ])),
    ]);

    try {
        $factory->provider->refreshToken('expired-refresh-token');
        test()->fail('Expected TokenRequestFailed.');
    } catch (TokenRequestFailed $e) {
        expect($e->status)->toBe(400)
            ->and($e->error)->toBe('invalid_grant');
    }
});
