<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin;

use Illuminate\Support\Carbon;
use Laravel\Socialite\Two\User as SocialiteUser;
use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\Exceptions\IdentityLevelNotMet;
use Spickyyy1\NhsLogin\Exceptions\InvalidVectorOfTrust;
use Spickyyy1\NhsLogin\Support\VectorOfTrust;

/**
 * The authenticated NHS login user.
 *
 * Beyond Socialite's id/name/email, this exposes the claims that actually
 * matter clinically: the NHS number, how strongly the identity was proven,
 * and the GP linkage details when those scopes were granted.
 */
final class NhsLoginUser extends SocialiteUser
{
    /** @var array<string, mixed> */
    public array $idTokenClaims = [];

    /**
     * The user's NHS number, if their identity has been matched to a PDS record.
     *
     * P0 users are authenticated but not identified, so this is null for them —
     * never assume it is present.
     */
    public function nhsNumber(): ?string
    {
        return $this->stringClaim('nhs_number');
    }

    /**
     * How strongly this identity was proven.
     *
     * Never throws, and fails closed. Every gate in the package rests on this,
     * so an unfamiliar vector — NHS login's vocabulary already reserves `Ck`
     * for a credential it has not shipped — must read as "not proven", not as
     * an exception taking every login on the estate with it.
     */
    public function identityProofingLevel(): IdentityProofingLevel
    {
        $claim = $this->stringClaim('identity_proofing_level');

        if ($claim !== null && $level = IdentityProofingLevel::tryFrom($claim)) {
            return $level;
        }

        $vot = $this->stringClaim('vot');
        $vector = $vot === null ? null : VectorOfTrust::tryParse($vot);

        return $vector === null ? IdentityProofingLevel::P0 : $vector->level;
    }

    /**
     * The vector exactly as NHS login sent it.
     *
     * Strict on purpose: a caller asking for the raw vector wants to know when
     * it cannot be understood. Code that only needs a decision should use
     * identityProofingLevel(), which fails closed instead.
     *
     * @throws InvalidVectorOfTrust
     */
    public function vectorOfTrust(): ?VectorOfTrust
    {
        $vot = $this->stringClaim('vot');

        return $vot === null ? null : VectorOfTrust::parse($vot);
    }

    /**
     * Whether the identity was proven against a PDS record (P5 or P9).
     */
    public function isIdentityVerified(): bool
    {
        return $this->identityProofingLevel()->isVerified();
    }

    /**
     * Fail loudly when the session is not proven to the level this app needs.
     *
     * Catch IdentityLevelNotMet and redirect through the flow again with a
     * higher vtr to trigger NHS login's step-up journey.
     *
     * @throws IdentityLevelNotMet
     */
    public function requireIdentityLevel(IdentityProofingLevel $minimum): self
    {
        $actual = $this->identityProofingLevel();

        if (! $actual->satisfies($minimum)) {
            throw new IdentityLevelNotMet($minimum, $actual);
        }

        return $this;
    }

    public function birthdate(): ?Carbon
    {
        $birthdate = $this->stringClaim('birthdate');

        return $birthdate === null ? null : Carbon::parse($birthdate);
    }

    public function familyName(): ?string
    {
        return $this->stringClaim('family_name') ?? $this->stringClaim('surname');
    }

    public function givenName(): ?string
    {
        return $this->stringClaim('given_name');
    }

    public function phoneNumber(): ?string
    {
        return $this->stringClaim('phone_number');
    }

    public function emailVerified(): bool
    {
        return $this->boolClaim('email_verified');
    }

    public function landlineNumber(): ?string
    {
        return $this->stringClaim('landline_number');
    }

    public function phoneNumberVerified(): bool
    {
        return $this->boolClaim('phone_number_verified');
    }

    public function landlineNumberVerified(): bool
    {
        return $this->boolClaim('landline_number_verified');
    }

    /**
     * When NHS login actually authenticated the user.
     *
     * Not the same as when your session started: an existing NHS login session
     * is reused, so this can be hours old on a fresh login to your app. Check
     * it before anything that warrants a recent authentication.
     */
    public function authenticatedAt(): ?Carbon
    {
        $authTime = $this->stringClaim('auth_time');

        return $authTime === null || ! is_numeric($authTime)
            ? null
            : Carbon::createFromTimestampUTC((int) $authTime);
    }

    public function gpOdsCode(): ?string
    {
        return $this->stringClaim('gp_ods_code') ?? $this->stringClaim('ods_code');
    }

    public function gpUserId(): ?string
    {
        return $this->stringClaim('gp_user_id') ?? $this->stringClaim('user_id');
    }

    public function gpLinkageKey(): ?string
    {
        return $this->stringClaim('gp_linkage_key') ?? $this->stringClaim('linkage_key');
    }

    /**
     * Any claim, in whatever shape NHS login sent it.
     *
     * The ID token is read first and the userinfo response only fills the gaps.
     * That ordering is the point: the ID token is signed and has been verified,
     * while the userinfo response is an HTTP body that arrived over a channel
     * authenticated by a bearer token. Where the two disagree about an NHS
     * number or an identity level, the signed one is the one that means
     * anything.
     *
     * The typed accessors above cover the scalar claims. This is the way in to
     * the structured ones — delegations and client_user_metadata — which have
     * no accessor yet because the flows around them are not modelled.
     */
    public function claim(string $name): mixed
    {
        return $this->idTokenClaims[$name] ?? $this->user[$name] ?? null;
    }

    /**
     * @return array<string, mixed>
     */
    public function idTokenClaims(): array
    {
        return $this->idTokenClaims;
    }

    /**
     * Read a claim as a string, from wherever it was sent.
     *
     * Which of the two sources carries a given claim depends on the scopes
     * granted, so callers should not have to know where to look. See claim()
     * for why the ID token is the one that wins.
     */
    private function stringClaim(string $name): ?string
    {
        $value = $this->claim($name);

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * NHS login sends the *_verified claims as real booleans, but they arrive
     * as strings through some proxies, so "false" must not read as true.
     */
    private function boolClaim(string $name): bool
    {
        return filter_var($this->claim($name), FILTER_VALIDATE_BOOL);
    }
}
