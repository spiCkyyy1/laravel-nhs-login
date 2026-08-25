<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Enums\AuthenticationCredential;
use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\Exceptions\InvalidVectorOfTrust;
use Spickyyy1\NhsLogin\Support\VectorOfTrust;

it('parses a full vector', function () {
    $vot = VectorOfTrust::parse('P9.Cp.Cd');

    expect($vot->level)->toBe(IdentityProofingLevel::P9)
        ->and($vot->credentials)->toBe([
            AuthenticationCredential::Cp,
            AuthenticationCredential::Cd,
        ])
        ->and((string) $vot)->toBe('P9.Cp.Cd');
});

it('parses a vector with a single credential', function () {
    expect((string) VectorOfTrust::parse('P5.Cm'))->toBe('P5.Cm');
});

it('rejects a vector with no identity proofing level', function () {
    VectorOfTrust::parse('Cp.Cd');
})->throws(InvalidVectorOfTrust::class, 'no identity proofing level');

it('rejects a vector declaring two levels', function () {
    VectorOfTrust::parse('P5.P9.Cp');
})->throws(InvalidVectorOfTrust::class, 'more than one identity proofing level');

it('rejects unknown components', function () {
    VectorOfTrust::parse('P9.Zz');
})->throws(InvalidVectorOfTrust::class, 'Unknown component [Zz]');

it('rejects an empty vector', function () {
    VectorOfTrust::parse('   ');
})->throws(InvalidVectorOfTrust::class);

it('compares levels', function () {
    expect(VectorOfTrust::parse('P9.Cp')->satisfies(IdentityProofingLevel::P5))->toBeTrue()
        ->and(VectorOfTrust::parse('P5.Cp')->satisfies(IdentityProofingLevel::P9))->toBeFalse()
        ->and(VectorOfTrust::parse('P0.Cp')->satisfies(IdentityProofingLevel::P0))->toBeTrue();
});

it('knows P0 is authenticated but not identified', function () {
    expect(IdentityProofingLevel::P0->isVerified())->toBeFalse()
        ->and(IdentityProofingLevel::P5->isVerified())->toBeTrue()
        ->and(IdentityProofingLevel::P9->isVerified())->toBeTrue();
});
