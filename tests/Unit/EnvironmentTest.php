<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Exceptions\NhsLoginConfigurationException;
use Spickyyy1\NhsLogin\Support\Environment;

$issuers = [
    'sandpit' => 'https://auth.sandpit.signin.nhs.uk',
    'integration' => 'https://auth.aos.signin.nhs.uk',
    'production' => 'https://auth.login.nhs.uk',
];

it('derives every endpoint from the issuer', function () use ($issuers) {
    $env = Environment::resolve('production', $issuers);

    expect($env->issuer)->toBe('https://auth.login.nhs.uk')
        ->and($env->authorizeEndpoint())->toBe('https://auth.login.nhs.uk/authorize')
        ->and($env->tokenEndpoint())->toBe('https://auth.login.nhs.uk/token')
        ->and($env->userInfoEndpoint())->toBe('https://auth.login.nhs.uk/userinfo')
        ->and($env->jwksUri())->toBe('https://auth.login.nhs.uk/.well-known/jwks.json');
});

it('maps the sandpit and integration environments', function () use ($issuers) {
    expect(Environment::resolve('sandpit', $issuers)->issuer)
        ->toBe('https://auth.sandpit.signin.nhs.uk')
        ->and(Environment::resolve('integration', $issuers)->issuer)
        ->toBe('https://auth.aos.signin.nhs.uk');
});

it('accepts an explicit issuer override and strips the trailing slash', function () use ($issuers) {
    expect(Environment::resolve('sandpit', $issuers, 'https://local.test/')->issuer)
        ->toBe('https://local.test');
});

it('names the valid environments when given an unknown one', function () use ($issuers) {
    Environment::resolve('staging', $issuers);
})->throws(NhsLoginConfigurationException::class, 'sandpit, integration, production');
