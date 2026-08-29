<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Events;

use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\NhsLoginUser;

/**
 * Dispatched once a login has been fully verified.
 *
 * The point of this event is the audit trail clinical services are expected
 * to keep (DCB0129, DSPT) without every application having to reach inside
 * the provider to build one. $subject and $identityProofingLevel are pulled
 * out separately so a listener can log "who signed in, proven to what level"
 * without touching claims at all; $user is still here for anything more a
 * listener genuinely needs, but nothing in this package will log it for you —
 * see the package README's security notes on why.
 */
final class NhsLoginAuthenticated
{
    public readonly string $subject;

    public readonly IdentityProofingLevel $identityProofingLevel;

    public function __construct(
        public readonly NhsLoginUser $user,
    ) {
        $this->subject = (string) $user->getId();
        $this->identityProofingLevel = $user->identityProofingLevel();
    }
}
