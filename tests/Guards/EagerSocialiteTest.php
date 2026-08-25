<?php

declare(strict_types=1);

use Laravel\Socialite\Facades\Socialite;
use Spickyyy1\NhsLogin\NhsLoginProvider;
use Spickyyy1\NhsLogin\Tests\EagerSocialiteTestCase;

uses(EagerSocialiteTestCase::class);

it('registers the driver when Socialite was already resolved before it booted', function () {
    // The other branch of registerSocialiteDriver(), and the one a real
    // application with its own Socialite driver takes. It goes through the same
    // Manager::extend() that rebinds $this — the machinery that has already
    // produced one shipped bug here.
    expect(Socialite::driver('nhslogin'))->toBeInstanceOf(NhsLoginProvider::class);
});

it('builds a working authorisation URL down that branch too', function () {
    $this->app['request']->setLaravelSession($this->app['session']->driver());

    $url = Socialite::driver('nhslogin')->redirect()->getTargetUrl();

    expect($url)->toStartWith('https://auth.sandpit.signin.nhs.uk/authorize');
});
