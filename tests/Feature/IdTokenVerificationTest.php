<?php

declare(strict_types=1);

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use GuzzleHttp\Psr7\Response;
use Spickyyy1\NhsLogin\Exceptions\InvalidIdToken;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;
use Spickyyy1\NhsLogin\Tests\RsaKeyPair;

/**
 * The ID token is the only proof of who signed in. Every case below must
 * abandon the session rather than fall back to the userinfo response, which
 * an attacker holding a stolen access token could also reach.
 */
function attemptLogin(?string $idToken, string $sessionNonce = 'test-nonce', bool $storeNonce = true): callable
{
    $request = ProviderFactory::request(['code' => 'auth-code', 'state' => 'st4te']);
    $request->session()->put('state', 'st4te');

    if ($storeNonce) {
        $request->session()->put('nhs_login.nonce', $sessionNonce);
    }

    $body = ['access_token' => 'access-token-value', 'expires_in' => 3600, 'scope' => 'openid profile'];

    if ($idToken !== null) {
        $body['id_token'] = $idToken;
    }

    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode($body)),
        new Response(200, ['Content-Type' => 'application/json'], json_encode(['sub' => 'nhs-sub-123'])),
    ], $request);

    return fn () => $factory->provider->user();
}

it('rejects a token signed by a key NHS login does not publish', function () {
    // Same kid, different key: this exercises signature verification itself,
    // not just the key-id lookup. Asserting on the cause matters — the wrapper
    // message is identical for every Firebase failure, so without this the
    // test would pass for a malformed header just as happily.
    $impostor = RsaKeyPair::generate(RsaKeyPair::shared()->kid);

    try {
        attemptLogin($impostor->signIdToken(idTokenClaims()))();
        $this->fail('Expected InvalidIdToken.');
    } catch (InvalidIdToken $e) {
        expect($e->getPrevious())->toBeInstanceOf(SignatureInvalidException::class);
    }
});

it('rejects a token whose key id is unknown', function () {
    $impostor = RsaKeyPair::generate('some-other-kid');

    attemptLogin($impostor->signIdToken(idTokenClaims()))();
})->throws(InvalidIdToken::class, 'signature could not be verified');

it('rejects a token from another issuer', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims([
        'iss' => 'https://auth.login.nhs.uk',
    ]));

    attemptLogin($idToken)();
})->throws(InvalidIdToken::class, 'was issued by [https://auth.login.nhs.uk]');

it('rejects a token addressed to a different client', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims(['aud' => 'someone-elses-client']));

    attemptLogin($idToken)();
})->throws(InvalidIdToken::class, 'not addressed to this client');

it('rejects a replayed token whose nonce does not match the session', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims(['nonce' => 'a-different-nonce']));

    attemptLogin($idToken)();
})->throws(InvalidIdToken::class, 'may have been replayed');

it('refuses to proceed when the session holds no nonce', function () {
    attemptLogin(RsaKeyPair::shared()->signIdToken(idTokenClaims()), storeNonce: false)();
})->throws(InvalidIdToken::class, 'No NHS login nonce was found');

it('rejects an expired token', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims([
        'iat' => time() - 7200,
        'exp' => time() - 3600,
    ]));

    try {
        attemptLogin($idToken)();
        $this->fail('Expected InvalidIdToken.');
    } catch (InvalidIdToken $e) {
        // Expiry specifically, rather than "rejected for some reason".
        expect($e->getPrevious())->toBeInstanceOf(ExpiredException::class);
    }
});

it('refuses a token that carries no expiry at all', function () {
    // JWT::decode only enforces exp when it is present, so a token without one
    // would otherwise verify for ever.
    $claims = idTokenClaims();
    unset($claims['exp']);

    attemptLogin(RsaKeyPair::shared()->signIdToken($claims))();
})->throws(InvalidIdToken::class, 'carries no expiry');

it('requires azp to name this client when the token lists several audiences', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims([
        'aud' => [ProviderFactory::CLIENT_ID, 'another-client'],
        'azp' => 'another-client',
    ]));

    attemptLogin($idToken)();
})->throws(InvalidIdToken::class, 'azp claim is not this client');

it('accepts several audiences when azp names this client', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims([
        'aud' => [ProviderFactory::CLIENT_ID, 'another-client'],
        'azp' => ProviderFactory::CLIENT_ID,
    ]));

    expect(attemptLogin($idToken)()->nhsNumber())->toBe('9912003888');
});

it('fails when the token response carries no id_token at all', function () {
    attemptLogin(null)();
})->throws(InvalidIdToken::class, 'did not return an ID token');

it('accepts a token that only just expired, within the configured leeway', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims([
        'exp' => time() - 5,
    ]));

    expect(attemptLogin($idToken)()->getId())->toBe('nhs-sub-123');
});

it('refuses a userinfo response describing a different subject', function () {
    // The access token and the ID token are separate credentials, and nothing
    // in the token response ties them to the same person. A substituted or
    // misrouted access token would otherwise hand back a verified identity for
    // one patient and an NHS number for another.
    $keys = RsaKeyPair::shared();

    $request = ProviderFactory::request(['code' => 'auth-code', 'state' => 'st4te']);
    $request->session()->put('state', 'st4te');
    $request->session()->put('nhs_login.nonce', 'test-nonce');

    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'access-token-value',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'id_token' => $keys->signIdToken(idTokenClaims(['sub' => 'nhs-sub-123'])),
        ])),
        new Response(200, ['Content-Type' => 'application/json'], json_encode(
            userInfo(['sub' => 'someone-else'])
        )),
    ], $request);

    expect(fn () => $factory->provider->user())
        ->toThrow(InvalidIdToken::class, 'different subject');
});

it('refuses a userinfo response carrying no subject at all', function () {
    $keys = RsaKeyPair::shared();

    $request = ProviderFactory::request(['code' => 'auth-code', 'state' => 'st4te']);
    $request->session()->put('state', 'st4te');
    $request->session()->put('nhs_login.nonce', 'test-nonce');

    $info = userInfo();
    unset($info['sub']);

    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'access-token-value',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'id_token' => $keys->signIdToken(idTokenClaims()),
        ])),
        new Response(200, ['Content-Type' => 'application/json'], json_encode($info)),
    ], $request);

    expect(fn () => $factory->provider->user())->toThrow(InvalidIdToken::class);
});

it('leaves the global JWT leeway exactly as it found it', function () {
    // Firebase stores leeway statically, so failing to restore it would change
    // how every other library in the request decodes its own tokens.
    JWT::$leeway = 7;

    try {
        attemptLogin(RsaKeyPair::shared()->signIdToken(idTokenClaims()))();

        expect(JWT::$leeway)->toBe(7);

        try {
            attemptLogin(RsaKeyPair::generate('nope')->signIdToken(idTokenClaims()))();
        } catch (InvalidIdToken) {
            // The failing path has to restore it too.
        }

        expect(JWT::$leeway)->toBe(7);
    } finally {
        JWT::$leeway = 0;
    }
});
