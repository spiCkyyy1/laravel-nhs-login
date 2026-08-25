<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Enums;

/**
 * NHS login identity proofing levels, ordered weakest to strongest.
 *
 * P0 proves only that someone controls an email address and mobile number.
 * P5 additionally matches them to a PDS record. P9 adds a physical comparison
 * between photographic ID and the person claiming it.
 */
enum IdentityProofingLevel: string
{
    case P0 = 'P0';
    case P5 = 'P5';
    case P9 = 'P9';

    /**
     * Whether this level satisfies the given minimum.
     */
    public function satisfies(self $minimum): bool
    {
        return $this->rank() >= $minimum->rank();
    }

    /**
     * Whether the user's identity has been verified against a PDS record.
     *
     * P0 users are authenticated but anonymous as far as the NHS is
     * concerned — they carry no NHS number.
     */
    public function isVerified(): bool
    {
        return $this !== self::P0;
    }

    public function description(): string
    {
        return match ($this) {
            self::P0 => 'Email address and mobile number verified',
            self::P5 => 'Matched to a Personal Demographics Service record',
            self::P9 => 'Photographic identity verified against the person',
        };
    }

    private function rank(): int
    {
        return match ($this) {
            self::P0 => 0,
            self::P5 => 5,
            self::P9 => 9,
        };
    }
}
