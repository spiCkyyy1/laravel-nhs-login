<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use GuzzleHttp\Psr7\Response;
use Spickyyy1\NhsLogin\ClientAssertion;
use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\Exceptions\IdentityLevelNotMet;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;
use Spickyyy1\NhsLogin\Tests\RsaKeyPair;

/**
 * Run a full callback: token endpoint, then userinfo.
 */
function completeLogin(?string $idToken = null, array $info = [], string $sessionNonce = 'test-nonce'): array
{
    $keys = RsaKeyPair::shared();

    $request = ProviderFactory::request(['code' => 'auth-code', 'state' => 'st4te']);
    $request->session()->put('state', 'st4te');
    $request->session()->put('nhs_login.nonce', $sessionNonce);

    $factory = ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'access-token-value',
            'refresh_token' => 'refresh-token-value',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'id_token' => $idToken ?? $keys->signIdToken(idTokenClaims()),
        ])),
        new Response(200, ['Content-Type' => 'application/json'], json_encode(userInfo($info))),
    ], $request);

    return [$factory, fn () => $factory->provider->user()];
}

it('authenticates with a signed assertion and never a client secret', function () {
    [$factory, $login] = completeLogin();

    $login();

    $body = $factory->transactions->getArrayCopy()[0]['request'];
    parse_str((string) $body->getBody(), $fields);

    expect($fields)->not->toHaveKey('client_secret')
        ->and($fields['grant_type'])->toBe('authorization_code')
        ->and($fields['client_assertion_type'])->toBe(ClientAssertion::TYPE)
        ->and($fields['client_assertion'])->not->toBeEmpty();
});

it('signs the client assertion with the claims NHS login requires', function () {
    [$factory, $login] = completeLogin();

    $login();

    parse_str((string) $factory->transactions->getArrayCopy()[0]['request']->getBody(), $fields);

    [$header, $payload] = array_map(
        static fn (string $part): array => json_decode(JWT::urlsafeB64Decode($part), true),
        array_slice(explode('.', $fields['client_assertion']), 0, 2),
    );

    expect($header['alg'])->toBe('RS512')
        ->and($header['kid'])->toBe(RsaKeyPair::shared()->kid)
        ->and($payload['iss'])->toBe(ProviderFactory::CLIENT_ID)
        ->and($payload['sub'])->toBe(ProviderFactory::CLIENT_ID)
        ->and($payload['aud'])->toBe(ProviderFactory::ISSUER.'/token')
        ->and($payload['jti'])->not->toBeEmpty()
        ->and($payload['exp'])->toBeGreaterThan(time());
});

it('returns a user carrying the NHS claims', function () {
    [, $login] = completeLogin();

    $user = $login();

    expect($user->getId())->toBe('nhs-sub-123')
        ->and($user->getName())->toBe('Aisha Khan')
        ->and($user->getEmail())->toBe('aisha.khan@example.test')
        ->and($user->nhsNumber())->toBe('9912003888')
        ->and($user->identityProofingLevel())->toBe(IdentityProofingLevel::P9)
        ->and($user->isIdentityVerified())->toBeTrue()
        ->and((string) $user->vectorOfTrust())->toBe('P9.Cp.Cd')
        ->and($user->birthdate()->toDateString())->toBe('1980-04-01')
        ->and($user->token)->toBe('access-token-value');
});

it('tolerates the trailing slash NHS login puts on its issuer claim', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims(['iss' => ProviderFactory::ISSUER.'/']));

    [, $login] = completeLogin($idToken);

    expect($login()->getId())->toBe('nhs-sub-123');
});

it('exposes an unverified P0 user without an NHS number', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims([
        'vot' => 'P0.Cp.Cd',
        'identity_proofing_level' => 'P0',
        'nhs_number' => null,
    ]));

    [, $login] = completeLogin($idToken, ['nhs_number' => null, 'identity_proofing_level' => 'P0']);

    $user = $login();

    expect($user->identityProofingLevel())->toBe(IdentityProofingLevel::P0)
        ->and($user->isIdentityVerified())->toBeFalse()
        ->and($user->nhsNumber())->toBeNull();
});

it('refuses a P5 session when P9 is required', function () {
    $idToken = RsaKeyPair::shared()->signIdToken(idTokenClaims([
        'vot' => 'P5.Cp.Cd',
        'identity_proofing_level' => 'P5',
    ]));

    [, $login] = completeLogin($idToken, ['identity_proofing_level' => 'P5']);

    $login()->requireIdentityLevel(IdentityProofingLevel::P9);
})->throws(IdentityLevelNotMet::class, 'returned identity proofing level P5, but P9 is required');

it('accepts a P9 session when P5 is required', function () {
    [, $login] = completeLogin();

    expect($login()->requireIdentityLevel(IdentityProofingLevel::P5)->nhsNumber())
        ->toBe('9912003888');
});
