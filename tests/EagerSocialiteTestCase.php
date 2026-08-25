<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;
use Laravel\Socialite\SocialiteManager;
use Laravel\Socialite\SocialiteServiceProvider;
use Spickyyy1\NhsLogin\NhsLoginServiceProvider;

/**
 * An application whose own service provider resolves Socialite during boot.
 *
 * That is ordinary — anyone registering a second custom driver does it — and it
 * takes the package down the branch where the factory is already resolved by
 * the time this package boots, rather than the afterResolving one every other
 * test exercises.
 */
class EagerSocialiteResolver extends ServiceProvider
{
    public function boot(): void
    {
        /** @var SocialiteManager $socialite */
        $socialite = $this->app->make(Factory::class);

        $socialite->extend('stub', static fn () => new \stdClass);
    }
}

class EagerSocialiteTestCase extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            SocialiteServiceProvider::class,
            EagerSocialiteResolver::class,
            NhsLoginServiceProvider::class,
        ];
    }
}
