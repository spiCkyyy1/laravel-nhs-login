<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

/**
 * The mock issuer switched on while the client still points at NHS login.
 */
class MisdirectedMockTestCase extends GuardedBootTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('nhs-login.mock.enabled', true);
        // Left pointed at the real sandpit, where the mock could never be hit.
        $app['config']->set('nhs-login.issuer', null);
    }
}
