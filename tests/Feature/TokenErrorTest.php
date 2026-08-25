<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Response;
use Spickyyy1\NhsLogin\Exceptions\TokenRequestFailed;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;

/**
 * Token endpoint rejections are almost always a misconfiguration, and the
 * response body names which one. Guzzle truncates that body in its own
 * exception message, so it has to be lifted out before it is lost.
 */
function exchangeReturning(Response $response): ProviderFactory
{
    $request = ProviderFactory::request(['code' => 'auth-code', 'state' => 'st4te']);
    $request->session()->put('state', 'st4te');
    $request->session()->put('nhs_login.nonce', 'test-nonce');

    return ProviderFactory::make([$response], $request);
}

it('surfaces the reason NHS login rejected the token request', function () {
    $factory = exchangeReturning(new Response(400, ['Content-Type' => 'application/json'], json_encode([
        'error' => 'invalid_client',
        'error_description' => 'Client assertion signature could not be verified',
    ])));

    try {
        $factory->provider->user();
        $this->fail('Expected TokenRequestFailed.');
    } catch (TokenRequestFailed $e) {
        expect($e->status)->toBe(400)
            ->and($e->error)->toBe('invalid_client')
            ->and($e->description)->toBe('Client assertion signature could not be verified')
            ->and($e->getMessage())->toContain('invalid_client');
    }
});

it('never copies the token response body into the message', function () {
    // A 4xx should not carry credentials, but the body is not ours to trust
    // with that, and this message is going into a log.
    $factory = exchangeReturning(new Response(400, ['Content-Type' => 'application/json'], json_encode([
        'error' => 'invalid_grant',
        'error_description' => 'Authorisation code has expired',
        'access_token' => 'leaked-token-value',
    ])));

    try {
        $factory->provider->user();
        $this->fail('Expected TokenRequestFailed.');
    } catch (TokenRequestFailed $e) {
        expect($e->getMessage())->not->toContain('leaked-token-value');
    }
});

it('does not call userinfo after the exchange fails', function () {
    $factory = exchangeReturning(new Response(401, [], json_encode(['error' => 'invalid_client'])));

    try {
        $factory->provider->user();
    } catch (TokenRequestFailed) {
        // expected
    }

    expect($factory->requestCount())->toBe(1);
});

it('handles a rejection that is not JSON at all', function () {
    $factory = exchangeReturning(new Response(502, ['Content-Type' => 'text/html'], '<html>Gateway Timeout</html>'));

    try {
        $factory->provider->user();
        $this->fail('Expected TokenRequestFailed.');
    } catch (TokenRequestFailed $e) {
        expect($e->status)->toBe(502)
            ->and($e->error)->toBeNull()
            ->and($e->getMessage())->not->toContain('<html>');
    }
});

it('rejects a 200 whose body is not the token response', function () {
    $factory = exchangeReturning(new Response(200, ['Content-Type' => 'text/html'], 'maintenance'));

    expect(fn () => $factory->provider->user())
        ->toThrow(TokenRequestFailed::class, 'could not be read as JSON');
});
