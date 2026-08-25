<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

/**
 * The mock reached by a host other than the one the request arrived on.
 *
 * Someone browsing 127.0.0.1 while APP_URL says localhost, or running the
 * issuer as a second instance on another port, is doing nothing wrong.
 */
class AlternateHostMockTestCase extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('nhs-login.mock.enabled', true);
        $app['config']->set('nhs-login.issuer', 'http://127.0.0.1:8001/nhs-login-mock');
    }
}
