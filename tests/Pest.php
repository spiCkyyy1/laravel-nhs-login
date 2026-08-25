<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Tests\MockIssuerTestCase;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;
use Spickyyy1\NhsLogin\Tests\TestCase;

uses(TestCase::class)->in('Feature', 'Unit');

// The mock issuer needs routes mounted, which means a different application.
uses(MockIssuerTestCase::class)->in('Mock');

function idTokenClaims(array $overrides = []): array
{
    return array_merge([
        'iss' => ProviderFactory::ISSUER,
        'aud' => ProviderFactory::CLIENT_ID,
        'sub' => 'nhs-sub-123',
        'iat' => time(),
        'exp' => time() + 300,
        'nonce' => 'test-nonce',
        'vot' => 'P9.Cp.Cd',
        'identity_proofing_level' => 'P9',
        'nhs_number' => '9912003888',
        'birthdate' => '1980-04-01',
    ], $overrides);
}

function userInfo(array $overrides = []): array
{
    return array_merge([
        'sub' => 'nhs-sub-123',
        'given_name' => 'Aisha',
        'family_name' => 'Khan',
        'email' => 'aisha.khan@example.test',
        'email_verified' => true,
        'nhs_number' => '9912003888',
        'birthdate' => '1980-04-01',
        'identity_proofing_level' => 'P9',
    ], $overrides);
}
