<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Exceptions;

/**
 * NHS login sent the user back without an authorisation code.
 *
 * The common case is not an error at all: the user tapped back or declined to
 * share their details, and NHS login returns error=access_denied with a
 * perfectly valid state. Callers should treat that as an abandoned login and
 * redirect quietly rather than reporting a failure.
 */
final class AuthorisationFailed extends NhsLoginException
{
    private const CANCELLED = 'access_denied';

    private function __construct(
        string $message,
        public readonly ?string $error = null,
        public readonly ?string $description = null,
    ) {
        parent::__construct($message);
    }

    public static function fromCallback(string $error, ?string $description = null): self
    {
        $error = self::sanitise($error);
        $description = $description === null ? null : self::sanitise($description);

        return new self(
            sprintf(
                'NHS login refused the authorisation request [%s]%s',
                $error,
                $description === null ? '.' : ": {$description}",
            ),
            $error,
            $description,
        );
    }

    public static function missingCode(): self
    {
        return new self(
            'NHS login returned no authorisation code and no error. The callback URL was '
            .'probably opened directly rather than reached by redirect.',
        );
    }

    /**
     * Whether the user abandoned the login rather than something going wrong.
     */
    public function wasCancelled(): bool
    {
        return $this->error === self::CANCELLED;
    }

    /**
     * These values arrive as query parameters, so anyone able to send the user
     * to the callback URL controls them. Strip anything that could forge a
     * second line in a log file, and cap the length.
     */
    private static function sanitise(string $value): string
    {
        $clean = preg_replace('/[^\P{C}]+/u', ' ', $value) ?? '';

        return mb_substr(trim($clean), 0, 200);
    }
}
