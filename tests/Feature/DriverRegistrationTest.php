<?php

declare(strict_types=1);

use Laravel\Socialite\Facades\Socialite;
use Spickyyy1\NhsLogin\NhsLoginProvider;

/**
 * Resolving through Socialite is how every application will reach this
 * provider, and it goes through machinery the package does not control:
 * Manager::extend() rebinds the callback it is given, so a registration that
 * looks correct can still fail the first time anyone calls it.
 */
beforeEach(function () {
    // redirect() stores the nonce in the session, which a container-resolved
    // request does not have until something puts one there.
    $this->app['request']->setLaravelSession($this->app['session']->driver());
});

it('resolves the driver through Socialite', function () {
    expect(Socialite::driver('nhslogin'))->toBeInstanceOf(NhsLoginProvider::class);
});

it('applies the configured scopes and vectors to the resolved driver', function () {
    config()->set('nhs-login.scopes', ['openid', 'profile', 'email']);
    config()->set('nhs-login.vtr', ['P5.Cp.Cd']);

    $url = Socialite::driver('nhslogin')->redirect()->getTargetUrl();

    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    expect($query['scope'])->toBe('openid profile email')
        ->and($query['vtr'])->toBe('["P5.Cp.Cd"]')
        ->and($query['client_id'])->toBe('test-client');
});

it('builds a redirect to the configured environment', function () {
    $url = Socialite::driver('nhslogin')->redirect()->getTargetUrl();

    expect($url)->toStartWith('https://auth.sandpit.signin.nhs.uk/authorize');
});
