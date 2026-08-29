<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Support;

use Laravel\Socialite\Two\Token;

/**
 * Socialite's Token, plus what a refresh needs that the base class has no
 * room for.
 *
 * NHS login is not obliged to return a new ID token on a refresh grant. When
 * it does, $idTokenClaims is the verified claim set — checked the same way
 * the original login's was, see NhsLoginProvider::refreshToken(). When it
 * does not, $idTokenClaims is null: the refresh proved the session is still
 * live, not anything new about identity.
 */
final class NhsLoginToken extends Token
{
    /**
     * @param  list<string>  $approvedScopes
     * @param  array<string, mixed>|null  $idTokenClaims
     */
    public function __construct(
        string $token,
        string $refreshToken,
        int $expiresIn,
        array $approvedScopes,
        public readonly ?array $idTokenClaims = null,
    ) {
        parent::__construct($token, $refreshToken, $expiresIn, $approvedScopes);
    }
}
