<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Exceptions;

use Throwable;

/**
 * NHS login's signing keys could not be obtained or made sense of.
 *
 * Distinct from InvalidIdToken on purpose: nothing is wrong with the token and
 * nothing is wrong with the user. The upstream key set is unreachable or
 * malformed, which is a transient failure worth retrying rather than a session
 * worth abandoning.
 */
final class JwksUnavailable extends NhsLoginException
{
    public static function unreachable(string $uri, Throwable $previous): self
    {
        return new self(
            "The NHS login key set at [{$uri}] could not be fetched: ".$previous->getMessage(),
            previous: $previous,
        );
    }

    public static function malformed(string $uri, ?Throwable $previous = null): self
    {
        return new self(
            "The NHS login key set at [{$uri}] is not a usable JWKS document."
            .($previous === null ? '' : ' '.$previous->getMessage()),
            previous: $previous,
        );
    }

    public static function noKeys(string $uri): self
    {
        return new self("The NHS login key set at [{$uri}] contains no keys.");
    }
}
