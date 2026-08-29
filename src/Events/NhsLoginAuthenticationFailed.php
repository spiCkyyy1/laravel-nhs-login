<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Events;

use Throwable;

/**
 * Dispatched whenever a login attempt does not complete.
 *
 * Every exception this package throws already carries a message safe to log
 * — see the individual exception classes, and AuthorisationFailed in
 * particular, which sanitises the query parameters NHS login sends before
 * they ever reach a message. $exception->getMessage() is fine to write to an
 * audit trail; the raw request this attempt arrived on is not, and a listener
 * should not go looking for it.
 *
 * A cancelled login (AuthorisationFailed::wasCancelled()) reaches here too.
 * That is by design — an audit trail that only records successes cannot
 * answer "did anyone try and fail" — but it is not an error worth alerting
 * on, and a listener that pages someone for every abandoned login will be
 * ignored within a week.
 */
final class NhsLoginAuthenticationFailed
{
    public function __construct(
        public readonly Throwable $exception,
    ) {}
}
