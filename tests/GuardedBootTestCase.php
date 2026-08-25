<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

use Throwable;

/**
 * Captures a failure raised while the service provider boots.
 *
 * The mock issuer's guards fire during boot — that is the whole point, since
 * a guard that waits until the first request has already let the routes be
 * mounted. Testing them means letting the application fail to start.
 */
abstract class GuardedBootTestCase extends TestCase
{
    protected ?Throwable $bootFailure = null;

    protected function setUp(): void
    {
        try {
            parent::setUp();
        } catch (Throwable $e) {
            $this->bootFailure = $e;
        }
    }

    protected function tearDown(): void
    {
        try {
            parent::tearDown();
        } catch (Throwable) {
            // The application never finished booting, so parts of the normal
            // teardown have nothing to tear down.
        }
    }
}
