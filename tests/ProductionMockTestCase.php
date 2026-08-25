<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

/**
 * The mock issuer switched on in production, which must not start.
 */
class ProductionMockTestCase extends GuardedBootTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['env'] = 'production';
        $app['config']->set('app.env', 'production');
        $app['config']->set('nhs-login.mock.enabled', true);
        // Correctly pointed at the mock, so only the environment guard can fire.
        $app['config']->set('nhs-login.issuer', 'http://localhost/nhs-login-mock');
    }
}
