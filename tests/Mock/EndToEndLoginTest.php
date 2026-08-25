<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\Exceptions\IdentityLevelNotMet;
use Spickyyy1\NhsLogin\IdTokenVerifier;
use Spickyyy1\NhsLogin\JwksResolver;
use Spickyyy1\NhsLogin\NhsLoginProvider;
use Spickyyy1\NhsLogin\NhsLoginUser;
use Spickyyy1\NhsLogin\Tests\LoopbackHttp;

/**
 * The halves of the suite meeting: a provider built by the container, talking
 * to the mock issuer over the package's own HTTP path, from redirect to user.
 *
 * Every other test either builds the provider by hand or drives the mock's
 * endpoints by hand. Both bugs this package has actually shipped lived in the
 * seam those leave open — the wiring between the container, Socialite and the
 * configuration.
 */
beforeEach(function () {
    $this->app['request']->setLaravelSession($this->app['session']->driver());
});

/**
 * Arrive at the callback as a fresh request carrying the same session.
 *
 * Dispatching the picker's POST rebinds the container's request, which the
 * provider follows by design — so the callback has to be modelled properly
 * rather than merged into whatever request happens to be current.
 *
 * @param  array<string, mixed>  $query
 */
function arriveAtCallback(string $url, array $query): void
{
    $request = Request::create($url, 'GET', $query);
    $request->setLaravelSession(app('session')->driver());

    app()->instance('request', $request);
}

function loopbackClient(): Client
{
    $client = LoopbackHttp::client(function (string $method, string $uri, array $parameters, array $server) {
        // The loopback stands in for a separate server, so dispatching into
        // this kernel must not disturb the request we are in the middle of.
        // Nothing in production dispatches into its own kernel; this is the
        // one place the two share a container.
        $current = app('request');

        try {
            return test()->call($method, $uri, $parameters, server: $server);
        } finally {
            app()->instance('request', $current);
        }
    });

    // The JWKS fetch has its own client, built by the service provider.
    app()->singleton(JwksResolver::class, fn () => new JwksResolver(
        $client,
        app('cache')->store(),
        (int) config('nhs-login.jwks_ttl'),
        (int) config('nhs-login.jwks_refresh_cooldown'),
    ));

    return $client;
}

/**
 * Drive a whole login the way an application would, and hand back the user.
 */
function signIn(array $form = []): NhsLoginUser
{
    $client = loopbackClient();

    /** @var NhsLoginProvider $provider */
    $provider = Socialite::driver('nhslogin');
    $provider->setHttpClient($client);

    parse_str((string) parse_url($provider->redirect()->getTargetUrl(), PHP_URL_QUERY), $query);

    $callback = test()->post('/nhs-login-mock/authorize', array_merge([
        'action' => 'approve',
        'client_id' => $query['client_id'],
        'redirect_uri' => $query['redirect_uri'],
        'state' => $query['state'] ?? null,
        'nonce' => $query['nonce'] ?? null,
        'scope' => $query['scope'],
        'vector' => 'P9.Cp.Cd',
    ], $form))->headers->get('Location');

    parse_str((string) parse_url((string) $callback, PHP_URL_QUERY), $returned);

    arriveAtCallback($query['redirect_uri'], $returned);

    /** @var NhsLoginProvider $callbackProvider */
    $callbackProvider = Socialite::driver('nhslogin');
    $callbackProvider->setHttpClient($client);

    return $callbackProvider->user();
}

it('completes a login from redirect to verified user', function () {
    $user = signIn();

    expect($user)->toBeInstanceOf(NhsLoginUser::class)
        ->and($user->nhsNumber())->toBe('9912003888')
        ->and($user->identityProofingLevel())->toBe(IdentityProofingLevel::P9)
        ->and($user->isIdentityVerified())->toBeTrue()
        ->and($user->getId())->toStartWith('mock-')
        ->and($user->token)->not->toBeEmpty()
        ->and($user->idTokenClaims())->toHaveKey('nonce');
});

it('carries the claims the issuer was asked to mint', function () {
    $user = signIn(['claims' => ['nhs_number' => '9000000009', 'given_name' => 'Test']]);

    expect($user->nhsNumber())->toBe('9000000009')
        ->and($user->givenName())->toBe('Test');
});

it('returns an unidentified user with no NHS number at P0', function () {
    $user = signIn(['vector' => 'P0.Cp']);

    expect($user->identityProofingLevel())->toBe(IdentityProofingLevel::P0)
        ->and($user->nhsNumber())->toBeNull()
        ->and(fn () => $user->requireIdentityLevel(IdentityProofingLevel::P5))
        ->toThrow(IdentityLevelNotMet::class);
});

it('completes a stateless login using the nonce it exposes', function () {
    // The stateless contract: redirect() generates a nonce, getNonce() is the
    // only way to learn it, and the callback instance must be handed it back.
    $client = loopbackClient();

    /** @var NhsLoginProvider $provider */
    $provider = Socialite::driver('nhslogin');
    $provider->setHttpClient($client)->stateless();

    parse_str((string) parse_url($provider->redirect()->getTargetUrl(), PHP_URL_QUERY), $query);

    $nonce = $provider->getNonce();

    expect($nonce)->not->toBeNull()
        ->and($query['nonce'])->toBe($nonce);

    $callback = test()->post('/nhs-login-mock/authorize', [
        'action' => 'approve',
        'client_id' => $query['client_id'],
        'redirect_uri' => $query['redirect_uri'],
        'nonce' => $nonce,
        'scope' => $query['scope'],
        'vector' => 'P9.Cp.Cd',
    ])->headers->get('Location');

    parse_str((string) parse_url((string) $callback, PHP_URL_QUERY), $returned);

    arriveAtCallback($query['redirect_uri'], $returned);

    /** @var NhsLoginProvider $callbackProvider */
    $callbackProvider = Socialite::driver('nhslogin');
    $callbackProvider->setHttpClient($client);

    $user = $callbackProvider->stateless()->nonce((string) $nonce)->user();

    expect($user->nhsNumber())->toBe('9912003888');
});

it('hands the configured leeway to the verifier', function () {
    // Nothing else proves a config value reaches the object that uses it,
    // because everything else constructs those objects directly.
    config()->set('nhs-login.leeway', 91);

    $verifier = app(IdTokenVerifier::class);

    expect((new ReflectionProperty($verifier, 'leeway'))->getValue($verifier))->toBe(91);
});
