<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Spickyyy1\NhsLogin\NhsLoginServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            SocialiteServiceProvider::class,
            NhsLoginServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('nhs-login.environment', 'sandpit');
        $app['config']->set('nhs-login.client_id', 'test-client');
        $app['config']->set('nhs-login.redirect', 'https://app.test/auth/nhs/callback');
        $app['config']->set('nhs-login.private_key', RsaKeyPair::shared()->privateKey());
        $app['config']->set('nhs-login.key_id', 'test-kid');
    }
}
