<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

/**
 * An application with the mock issuer mounted, configured the way the README
 * tells a developer to configure it.
 */
abstract class MockIssuerTestCase extends TestCase
{
    protected const PREFIX = 'nhs-login-mock';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.url', 'http://localhost');
        $app['config']->set('nhs-login.issuer', 'http://localhost/'.self::PREFIX);
        $app['config']->set('nhs-login.redirect', 'http://localhost/auth/nhs/callback');
        $app['config']->set('nhs-login.mock.enabled', true);
        $app['config']->set('nhs-login.mock.prefix', self::PREFIX);
    }
}
