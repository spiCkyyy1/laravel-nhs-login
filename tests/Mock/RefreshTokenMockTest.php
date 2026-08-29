<?php

declare(strict_types=1);

use Laravel\Socialite\Facades\Socialite;
use Spickyyy1\NhsLogin\Exceptions\TokenRequestFailed;
use Spickyyy1\NhsLogin\NhsLoginProvider;
use Spickyyy1\NhsLogin\Support\NhsLoginToken;

/**
 * The mock plays the refresh grant the same way it plays the rest of the
 * protocol: rotating the refresh token on every use, so a client that does
 * not persist the new one finds out here rather than in the sandpit.
 *
 * signIn() and loopbackClient() are declared in EndToEndLoginTest, which
 * every file under Mock/ shares — see MockFlow's docblock on why these
 * stayed functions rather than becoming a second helper class.
 */
beforeEach(function () {
    $this->app['request']->setLaravelSession($this->app['session']->driver());
});

it('redeems a refresh token for a new access token', function () {
    $user = signIn();

    $client = loopbackClient();

    /** @var NhsLoginProvider $provider */
    $provider = Socialite::driver('nhslogin');
    $provider->setHttpClient($client);

    $token = $provider->refreshToken($user->refreshToken, $user->getId());

    expect($token)->toBeInstanceOf(NhsLoginToken::class)
        ->and($token->token)->not->toBeEmpty()
        ->and($token->token)->not->toBe($user->token)
        ->and($token->refreshToken)->not->toBe($user->refreshToken)
        ->and($token->idTokenClaims)->not->toBeNull()
        ->and($token->idTokenClaims['sub'])->toBe($user->getId());
});

it('refuses to redeem the same refresh token twice', function () {
    $user = signIn();

    $client = loopbackClient();

    /** @var NhsLoginProvider $provider */
    $provider = Socialite::driver('nhslogin');
    $provider->setHttpClient($client);

    $provider->refreshToken($user->refreshToken);

    expect(fn () => $provider->refreshToken($user->refreshToken))
        ->toThrow(TokenRequestFailed::class);
});
