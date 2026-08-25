<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Enums;

/**
 * The credential components of a Vector of Trust.
 */
enum AuthenticationCredential: string
{
    /** Email address and password. */
    case Cp = 'Cp';

    /** A device associated with the account (symmetric). */
    case Cd = 'Cd';

    /** A shared cryptographic key. Reserved by NHS login; not yet implemented. */
    case Ck = 'Ck';

    /** A FIDO-compliant device associated with the account (asymmetric). */
    case Cm = 'Cm';

    public function description(): string
    {
        return match ($this) {
            self::Cp => 'Email address and password',
            self::Cd => 'Associated device',
            self::Ck => 'Shared cryptographic key',
            self::Cm => 'FIDO-compliant associated device',
        };
    }
}
