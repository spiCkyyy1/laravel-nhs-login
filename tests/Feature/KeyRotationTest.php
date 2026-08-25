<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Response;
use Spickyyy1\NhsLogin\Exceptions\InvalidIdToken;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;
use Spickyyy1\NhsLogin\Tests\RsaKeyPair;

/**
 * NHS login rotates its signing keys without announcing it. A cached key set
 * that no longer contains the signing key would reject every login until the
 * cache expired — an outage lasting as long as the TTL, caused by a routine
 * operation at the other end.
 *
 * @param  list<list<RsaKeyPair>>  $jwksSets  served in turn, the last repeating
 */
function loginSignedBy(RsaKeyPair $signer, array $jwksSets): ProviderFactory
{
    $request = ProviderFactory::request(['code' => 'auth-code', 'state' => 'st4te']);
    $request->session()->put('state', 'st4te');
    $request->session()->put('nhs_login.nonce', 'test-nonce');

    return ProviderFactory::make([
        new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => 'access-token-value',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'id_token' => $signer->signIdToken(idTokenClaims()),
        ])),
        new Response(200, ['Content-Type' => 'application/json'], json_encode(userInfo())),
    ], $request, $jwksSets);
}

it('re-fetches the key set when the token names a key it does not hold', function () {
    $old = RsaKeyPair::shared();
    $new = RsaKeyPair::generate('rotated-kid');

    // Published set catches up only on the second fetch.
    $factory = loginSignedBy($new, [[$old], [$old, $new]]);

    $user = $factory->provider->user();

    expect($user->nhsNumber())->toBe('9912003888')
        ->and($factory->jwksFetchCount())->toBe(2);
});

it('does not re-fetch when the signing key is already known', function () {
    $keys = RsaKeyPair::shared();

    $factory = loginSignedBy($keys, [[$keys]]);

    $factory->provider->user();

    expect($factory->jwksFetchCount())->toBe(1);
});

it('still rejects the token when the refreshed set does not contain the key either', function () {
    $unknown = RsaKeyPair::generate('never-published');

    $factory = loginSignedBy($unknown, [[RsaKeyPair::shared()]]);

    expect(fn () => $factory->provider->user())->toThrow(InvalidIdToken::class);

    // One speculative re-fetch, then it gives up.
    expect($factory->jwksFetchCount())->toBe(2);
});
