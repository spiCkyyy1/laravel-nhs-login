<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Exceptions;

use Psr\Http\Message\ResponseInterface;
use Spickyyy1\NhsLogin\Support\ErrorResponse;
use Throwable;

/**
 * The token endpoint rejected the request.
 *
 * Almost always a configuration problem rather than a user problem —
 * invalid_client means the assertion did not verify against the public key NHS
 * login holds for you, and invalid_grant usually means the redirect_uri does
 * not match the one registered. Guzzle truncates the response body in its own
 * exception message, which hides exactly the field that says which.
 */
final class TokenRequestFailed extends NhsLoginException
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
                'NHS login rejected the token request (HTTP %d)%s%s',
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

    /**
     * A 2xx whose body is not the JSON token response it must be.
     */
    public static function malformed(ResponseInterface $response): self
    {
        return new self(
            sprintf(
                'NHS login returned a token response that could not be read as JSON (HTTP %d).',
                $response->getStatusCode(),
            ),
            $response->getStatusCode(),
            null,
            null,
            null,
        );
    }
}
