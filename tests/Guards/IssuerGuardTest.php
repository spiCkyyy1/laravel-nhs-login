<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Exceptions\NhsLoginConfigurationException;
use Spickyyy1\NhsLogin\Tests\MisdirectedMockTestCase;

uses(MisdirectedMockTestCase::class);

it('says so when the mock is enabled but the client points elsewhere', function () {
    // Otherwise the routes mount, nothing ever reaches them, and the login
    // fails against the real issuer for no visible reason.
    expect($this->bootFailure)
        ->toBeInstanceOf(NhsLoginConfigurationException::class)
        ->and($this->bootFailure->getMessage())
        ->toContain('auth.sandpit.signin.nhs.uk')
        ->toContain('NHS_LOGIN_ISSUER');
});
