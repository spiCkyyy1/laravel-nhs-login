<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Exceptions;

use Psr\Http\Message\ResponseInterface;
use Spickyyy1\NhsLogin\Support\ErrorResponse;
use Throwable;

/**
 * The userinfo endpoint would not describe the user.
 *
 * Reached after the ID token has already verified, so the identity is known —
 * what failed is the profile lookup. A 401 usually means the access token has
 * expired between the two calls; anything else is NHS login having a bad day.
 */
final class UserInfoRequestFailed extends NhsLoginException
{
    private function __construct(
        string $message,
        public readonly int $status,
        public readonly ?string $error,
        public readonly ?string $description,
        ?Throwable $previous,
    ) {
        parent::__construct($message, previous: $previous);
    }

    public static function fromResponse(?ResponseInterface $response, ?Throwable $previous = null): self
    {
        $status = $response?->getStatusCode() ?? 0;
        [$error, $description] = ErrorResponse::extract($response);

        return new self(
            sprintf(
                'NHS login rejected the userinfo request (HTTP %d)%s%s',
                $status,
                $error === null ? '' : ": {$error}",
                $description === null ? '.' : " — {$description}",
            ),
            $status,
            $error,
            $description,
            $previous,
        );
    }

    public static function malformed(ResponseInterface $response): self
    {
        return new self(
            sprintf(
                'The NHS login userinfo response could not be read as JSON (HTTP %d).',
                $response->getStatusCode(),
            ),
            $response->getStatusCode(),
            null,
            null,
            null,
        );
    }
}
