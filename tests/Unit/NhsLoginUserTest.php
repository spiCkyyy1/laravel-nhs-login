<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\Exceptions\InvalidVectorOfTrust;
use Spickyyy1\NhsLogin\NhsLoginUser;

/**
 * Which of userinfo and the ID token carries a given claim depends on the
 * scopes granted at registration, so callers should never have to know.
 */
function nhsUser(array $userInfo = [], array $idTokenClaims = []): NhsLoginUser
{
    $user = new NhsLoginUser;
    $user->setRaw($userInfo);
    $user->idTokenClaims = $idTokenClaims;

    return $user;
}

it('prefers the signed ID token over the userinfo response', function () {
    // The userinfo body is unsigned. If the two ever disagree about an NHS
    // number, believing the unsigned one is how a patient gets someone else's
    // record.
    $user = nhsUser(['nhs_number' => '9000000009'], ['nhs_number' => '9912003888']);

    expect($user->nhsNumber())->toBe('9912003888');
});

it('prefers the ID token for the claims identity decisions are made on', function () {
    $user = nhsUser(
        ['identity_proofing_level' => 'P9', 'vot' => 'P9.Cp.Cd'],
        ['identity_proofing_level' => 'P0', 'vot' => 'P0.Cp'],
    );

    expect($user->identityProofingLevel())->toBe(IdentityProofingLevel::P0)
        ->and($user->isIdentityVerified())->toBeFalse();
});

it('falls back to userinfo when the ID token omits the claim', function () {
    // Which source carries a claim depends on the scopes granted, so the
    // fallback is normal rather than suspicious.
    $user = nhsUser(['nhs_number' => '9912003888'], []);

    expect($user->nhsNumber())->toBe('9912003888');
});

it('reads the landline claims', function () {
    $user = nhsUser([
        'landline_number' => '01612345678',
        'landline_number_verified' => true,
    ]);

    expect($user->landlineNumber())->toBe('01612345678')
        ->and($user->landlineNumberVerified())->toBeTrue();
});

it('does not read the string "false" as verified', function () {
    // Booleans survive JSON intact, but not every proxy in front of an NHS
    // integration leaves the body alone.
    $user = nhsUser(['email_verified' => 'false', 'phone_number_verified' => '0']);

    expect($user->emailVerified())->toBeFalse()
        ->and($user->phoneNumberVerified())->toBeFalse();
});

it('reads the verified claims when they are genuinely true', function () {
    $user = nhsUser(['email_verified' => true, 'phone_number_verified' => 'true']);

    expect($user->emailVerified())->toBeTrue()
        ->and($user->phoneNumberVerified())->toBeTrue();
});

it('exposes when NHS login actually authenticated the user', function () {
    $user = nhsUser([], ['auth_time' => 1_700_000_000]);

    expect($user->authenticatedAt()?->timestamp)->toBe(1_700_000_000);
});

it('returns no authentication time when the claim is absent or unusable', function () {
    expect(nhsUser()->authenticatedAt())->toBeNull()
        ->and(nhsUser([], ['auth_time' => 'yesterday'])->authenticatedAt())->toBeNull();
});

it('gives access to structured claims that have no accessor', function () {
    $delegations = [['delegate_sub' => 'nhs-sub-999', 'relationship' => 'parent']];

    $user = nhsUser([], ['delegations' => $delegations]);

    expect($user->claim('delegations'))->toBe($delegations)
        ->and($user->claim('nothing_here'))->toBeNull();
});

it('does not flatten a structured claim into a string accessor', function () {
    $user = nhsUser([], ['nhs_number' => ['unexpected']]);

    expect($user->nhsNumber())->toBeNull();
});

it('treats an unproven identity as P0 rather than guessing', function () {
    expect(nhsUser()->identityProofingLevel())->toBe(IdentityProofingLevel::P0)
        ->and(nhsUser()->isIdentityVerified())->toBeFalse();
});

it('falls back to the surname claim when family_name is absent', function () {
    // Which of the two NHS login sends depends on the scopes granted.
    expect(nhsUser([], ['surname' => 'Khan'])->familyName())->toBe('Khan')
        ->and(nhsUser([], ['family_name' => 'Khan', 'surname' => 'Ignored'])->familyName())->toBe('Khan');
});

it('falls back to the unprefixed GP claims', function () {
    $user = nhsUser([], ['ods_code' => 'A81001', 'user_id' => 'u-1', 'linkage_key' => 'lk-1']);

    expect($user->gpOdsCode())->toBe('A81001')
        ->and($user->gpUserId())->toBe('u-1')
        ->and($user->gpLinkageKey())->toBe('lk-1');
});

it('prefers the prefixed GP claims when both are present', function () {
    $user = nhsUser([], [
        'gp_ods_code' => 'B82002', 'ods_code' => 'A81001',
        'gp_user_id' => 'u-2', 'user_id' => 'u-1',
        'gp_linkage_key' => 'lk-2', 'linkage_key' => 'lk-1',
    ]);

    expect($user->gpOdsCode())->toBe('B82002')
        ->and($user->gpUserId())->toBe('u-2')
        ->and($user->gpLinkageKey())->toBe('lk-2');
});

it('derives the identity level from vot when the explicit claim is missing', function () {
    expect(nhsUser([], ['vot' => 'P5.Cp.Cd'])->identityProofingLevel())
        ->toBe(IdentityProofingLevel::P5);
});

it('treats an unrecognised vector as unproven rather than throwing', function () {
    // NHS login's vocabulary grows — Ck is already reserved for a credential it
    // has not shipped. A gate that throws takes every login with it.
    $user = nhsUser([], ['vot' => 'P9.Cz']);

    expect($user->identityProofingLevel())->toBe(IdentityProofingLevel::P0)
        ->and($user->isIdentityVerified())->toBeFalse();
});

it('still reports an unparseable vector to anyone who asks for it directly', function () {
    expect(fn () => nhsUser([], ['vot' => 'P9.Cz'])->vectorOfTrust())
        ->toThrow(InvalidVectorOfTrust::class);
});
