<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Exceptions\NhsLoginConfigurationException;
use Spickyyy1\NhsLogin\Tests\ProductionMockTestCase;

uses(ProductionMockTestCase::class);

it('refuses to mount the mock issuer outside local and testing', function () {
    // It signs ID tokens this application will accept for any NHS number that
    // is typed into a form. Anywhere but a laptop, that is an auth bypass.
    expect($this->bootFailure)
        ->toBeInstanceOf(NhsLoginConfigurationException::class)
        ->and($this->bootFailure->getMessage())
        ->toContain('production')
        ->toContain('NHS_LOGIN_MOCK');
});
