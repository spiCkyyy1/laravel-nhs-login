<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Exceptions;

use Throwable;

/**
 * The ID token returned by NHS login could not be trusted.
 *
 * Every failure here means the session must be abandoned — a token that fails
 * verification proves nothing about who the user is.
 */
final class InvalidIdToken extends NhsLoginException
{
    public static function missing(): self
    {
        return new self('NHS login did not return an ID token. The token response was incomplete.');
    }

    public static function unverifiable(Throwable $previous): self
    {
        return new self(
            'The NHS login ID token signature could not be verified: '.$previous->getMessage(),
            previous: $previous,
        );
    }

    public static function issuerMismatch(string $expected, string $actual): self
    {
        return new self("The ID token was issued by [{$actual}], expected [{$expected}].");
    }

    public static function audienceMismatch(string $clientId): self
    {
        return new self("The ID token is not addressed to this client [{$clientId}].");
    }

    public static function subjectMismatch(): self
    {
        return new self(
            'The userinfo response describes a different subject than the ID token. '
            .'The session cannot be attributed to a user and must be abandoned.',
        );
    }

    public static function refreshedSubjectMismatch(): self
    {
        return new self(
            'The ID token returned alongside a refreshed access token names a different subject '
            .'than expected. The refresh must be rejected rather than trusted for the wrong person.',
        );
    }

    public static function nonceMismatch(): self
    {
        return new self(
            'The ID token nonce did not match the one sent with the authorisation request. '
            .'This request may have been replayed.',
        );
    }

    public static function missingNonce(): self
    {
        return new self('No NHS login nonce was found in the session. Start the login flow again.');
    }

    public static function missingStatelessNonce(): self
    {
        return new self(
            'No nonce was supplied for this stateless NHS login callback. Read getNonce() after '
            .'redirect(), persist it, and pass it back with nonce() before calling user().',
        );
    }

    public static function missingExpiry(): self
    {
        return new self('The NHS login ID token carries no expiry and cannot be trusted.');
    }

    public static function authorizedPartyMismatch(string $clientId): self
    {
        return new self(
            "The ID token names several audiences but its azp claim is not this client [{$clientId}]."
        );
    }
}
