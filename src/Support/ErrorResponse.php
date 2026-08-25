<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Support;

use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * Lifts the two documented OAuth error fields out of a failed response.
 *
 * The body is never copied wholesale. A token response carries credentials,
 * and these values end up in an exception message that is going somewhere it
 * can be read.
 */
final class ErrorResponse
{
    private const MAX_LENGTH = 200;

    /**
     * @return array{0: ?string, 1: ?string} the error and its description
     */
    public static function extract(?ResponseInterface $response): array
    {
        if ($response === null) {
            return [null, null];
        }

        try {
            $decoded = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return [null, null];
        }

        if (! is_array($decoded)) {
            return [null, null];
        }

        return [
            self::string($decoded['error'] ?? null),
            self::string($decoded['error_description'] ?? null),
        ];
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? mb_substr($value, 0, self::MAX_LENGTH) : null;
    }
}
