<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Testing;

use Illuminate\Http\JsonResponse;
use Spickyyy1\NhsLogin\Exceptions\NhsLoginException;

/**
 * The mock issuer refusing a request, in the shape NHS login would refuse it.
 *
 * Deliberately more talkative than the real thing: the description says what
 * was wrong with the assertion rather than just naming the error, because the
 * point of running this locally is to find that out.
 */
final class MockIssuerRejection extends NhsLoginException
{
    private function __construct(
        string $message,
        public readonly string $error,
        public readonly int $status,
    ) {
        parent::__construct($message);
    }

    public static function invalidClient(string $detail): self
    {
        return new self($detail, 'invalid_client', 401);
    }

    public static function invalidGrant(string $detail): self
    {
        return new self($detail, 'invalid_grant', 400);
    }

    public static function invalidRequest(string $detail): self
    {
        return new self($detail, 'invalid_request', 400);
    }

    public static function serverError(string $detail): self
    {
        return new self($detail, 'server_error', 500);
    }

    public function toResponse(): JsonResponse
    {
        return new JsonResponse([
            'error' => $this->error,
            'error_description' => $this->getMessage(),
        ], $this->status);
    }
}
