<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Tests\AlternateHostMockTestCase;

uses(AlternateHostMockTestCase::class);

it('mounts the mock even when the issuer host is not the request host', function () {
    $this->get('/nhs-login-mock/.well-known/jwks.json')
        ->assertOk()
        ->assertJsonPath('keys.0.alg', 'RS512');
});

it('still reports the issuer it was configured with', function () {
    $this->get('/nhs-login-mock/.well-known/openid-configuration')
        ->assertJsonPath('issuer', 'http://127.0.0.1:8001/nhs-login-mock');
});
