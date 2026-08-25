<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Support;

use Spickyyy1\NhsLogin\Enums\AuthenticationCredential;
use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\Exceptions\InvalidVectorOfTrust;

/**
 * A single Vector of Trust, e.g. "P9.Cp.Cd".
 *
 * Components within a vector are ANDed; separate vectors in a vtr request are
 * ORed. The identity proofing level is always present; credentials are not
 * (the vot returned for a P0 session may carry only credentials).
 */
final readonly class VectorOfTrust implements \Stringable
{
    /**
     * @param  list<AuthenticationCredential>  $credentials
     */
    public function __construct(
        public IdentityProofingLevel $level,
        public array $credentials = [],
    ) {}

    /**
     * Parse a dot-delimited vector as it appears in a vot claim.
     *
     * @throws InvalidVectorOfTrust
     */
    public static function parse(string $vector): self
    {
        $parts = array_filter(explode('.', trim($vector)));

        if ($parts === []) {
            throw InvalidVectorOfTrust::empty();
        }

        $level = null;
        $credentials = [];

        foreach ($parts as $part) {
            if ($proofing = IdentityProofingLevel::tryFrom($part)) {
                if ($level !== null) {
                    throw InvalidVectorOfTrust::duplicateLevel($vector);
                }

                $level = $proofing;

                continue;
            }

            if ($credential = AuthenticationCredential::tryFrom($part)) {
                $credentials[] = $credential;

                continue;
            }

            throw InvalidVectorOfTrust::unknownComponent($part, $vector);
        }

        if ($level === null) {
            throw InvalidVectorOfTrust::missingLevel($vector);
        }

        return new self($level, $credentials);
    }

    /**
     * Parse, or null if it cannot be parsed.
     *
     * For the places that must reach a decision whatever NHS login sent —
     * a vocabulary that grows is a normal event, not an error to propagate.
     */
    public static function tryParse(string $vector): ?self
    {
        try {
            return self::parse($vector);
        } catch (InvalidVectorOfTrust) {
            return null;
        }
    }

    public function satisfies(IdentityProofingLevel $minimum): bool
    {
        return $this->level->satisfies($minimum);
    }

    public function __toString(): string
    {
        return implode('.', [
            $this->level->value,
            ...array_map(
                static fn (AuthenticationCredential $credential): string => $credential->value,
                $this->credentials,
            ),
        ]);
    }
}
