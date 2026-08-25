<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Exceptions;

use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;

/**
 * The user authenticated, but not to the identity level the application needs.
 *
 * Recoverable: send them back through the flow with a higher vtr to trigger a
 * step-up journey, rather than treating it as a failed login.
 */
final class IdentityLevelNotMet extends NhsLoginException
{
    public function __construct(
        public readonly IdentityProofingLevel $required,
        public readonly IdentityProofingLevel $actual,
    ) {
        parent::__construct(sprintf(
            'NHS login returned identity proofing level %s, but %s is required.',
            $actual->value,
            $required->value,
        ));
    }
}
