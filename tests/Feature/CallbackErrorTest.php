<?php

declare(strict_types=1);

use Laravel\Socialite\Two\InvalidStateException;
use Spickyyy1\NhsLogin\Exceptions\AuthorisationFailed;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;

/**
 * Coming back from NHS login without a code is ordinary, not exceptional:
 * users change their minds. It must not surface as an HTTP failure from the
 * token endpoint, which is what posting the absent code would produce.
 */
function callbackWith(array $query): callable
{
    $request = ProviderFactory::request($query + ['state' => 'st4te']);
    $request->session()->put('state', 'st4te');
    $request->session()->put('nhs_login.nonce', 'test-nonce');

    $factory = ProviderFactory::make([], $request);

    return function () use ($factory) {
        try {
            return $factory->provider->user();
        } finally {
            expect($factory->requestCount())->toBe(0, 'no HTTP call should be made without a code');
        }
    };
}

it('reports a cancelled login as cancelled', function () {
    $login = callbackWith([
        'error' => 'access_denied',
        'error_description' => 'User cancelled the journey',
    ]);

    try {
        $login();
        $this->fail('Expected AuthorisationFailed.');
    } catch (AuthorisationFailed $e) {
        expect($e->wasCancelled())->toBeTrue()
            ->and($e->error)->toBe('access_denied')
            ->and($e->description)->toBe('User cancelled the journey');
    }
});

it('does not treat every callback error as a cancellation', function () {
    try {
        callbackWith(['error' => 'invalid_request'])();
        $this->fail('Expected AuthorisationFailed.');
    } catch (AuthorisationFailed $e) {
        expect($e->wasCancelled())->toBeFalse()
            ->and($e->error)->toBe('invalid_request')
            ->and($e->description)->toBeNull();
    }
});

it('strips control characters out of the error it was handed', function () {
    // The callback URL is reachable by anyone, so these values are hostile
    // input on their way to a log file.
    try {
        callbackWith([
            'error' => "access_denied\n",
            'error_description' => "cancelled\r\nWARNING: fake log line",
        ])();
        $this->fail('Expected AuthorisationFailed.');
    } catch (AuthorisationFailed $e) {
        expect($e->error)->toBe('access_denied')
            ->and($e->description)->not->toContain("\n")
            ->and($e->description)->not->toContain("\r")
            ->and($e->getMessage())->not->toContain("\n");
    }
});

it('caps an overlong error description', function () {
    try {
        callbackWith(['error' => 'server_error', 'error_description' => str_repeat('a', 5000)])();
        $this->fail('Expected AuthorisationFailed.');
    } catch (AuthorisationFailed $e) {
        expect(mb_strlen((string) $e->description))->toBe(200);
    }
});

it('explains a callback that carries neither code nor error', function () {
    expect(fn () => callbackWith([])())
        ->toThrow(AuthorisationFailed::class, 'no authorisation code');
});

it('leaves no reusable nonce behind when the login is abandoned', function () {
    $request = ProviderFactory::request(['error' => 'access_denied', 'state' => 'st4te']);
    $request->session()->put('state', 'st4te');
    $request->session()->put('nhs_login.nonce', 'test-nonce');

    $factory = ProviderFactory::make([], $request);

    try {
        $factory->provider->user();
    } catch (AuthorisationFailed) {
        // expected
    }

    expect($request->session()->has('nhs_login.nonce'))->toBeFalse();
});

it('checks the state before it looks at the error', function () {
    $request = ProviderFactory::request(['error' => 'access_denied', 'state' => 'forged']);
    $request->session()->put('state', 'st4te');

    $factory = ProviderFactory::make([], $request);

    expect(fn () => $factory->provider->user())->toThrow(InvalidStateException::class);
});
