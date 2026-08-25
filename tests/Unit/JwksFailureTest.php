<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Spickyyy1\NhsLogin\Exceptions\JwksUnavailable;
use Spickyyy1\NhsLogin\JwksResolver;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;
use Spickyyy1\NhsLogin\Tests\RsaKeyPair;

/**
 * A bad key set is an upstream failure, not a bad token. It has to surface as
 * a package exception rather than a raw SPL one, and — the part that actually
 * hurts — it must never be written to the cache, or a single malformed
 * response becomes an outage lasting the whole TTL.
 *
 * @return array{0: JwksResolver, 1: Repository}
 */
function resolverServing(array $responses): array
{
    $cache = new Repository(new ArrayStore);

    $resolver = new JwksResolver(
        new Client(['handler' => HandlerStack::create(new MockHandler($responses))]),
        $cache,
    );

    return [$resolver, $cache];
}

function jwksJson(array $document): Response
{
    return new Response(200, ['Content-Type' => 'application/json'], json_encode($document));
}

it('reports an empty key set as unavailable rather than crashing', function () {
    [$resolver] = resolverServing([jwksJson(['keys' => []])]);

    expect(fn () => $resolver->keys(ProviderFactory::JWKS_URI))
        ->toThrow(JwksUnavailable::class, 'contains no keys');
});

it('reports a document that is not a key set', function () {
    [$resolver] = resolverServing([jwksJson(['nope' => true])]);

    expect(fn () => $resolver->keys(ProviderFactory::JWKS_URI))
        ->toThrow(JwksUnavailable::class, 'not a usable JWKS');
});

it('reports a body that is not JSON at all', function () {
    // What a captive portal or an error page served with a 200 looks like.
    [$resolver] = resolverServing([
        new Response(200, ['Content-Type' => 'text/html'], '<html>Sign in to the wifi</html>'),
    ]);

    expect(fn () => $resolver->keys(ProviderFactory::JWKS_URI))->toThrow(JwksUnavailable::class);
});

it('reports an unreachable endpoint', function () {
    [$resolver] = resolverServing([new Response(503, [], 'unavailable')]);

    expect(fn () => $resolver->keys(ProviderFactory::JWKS_URI))
        ->toThrow(JwksUnavailable::class, 'could not be fetched');
});

it('does not cache a key set it could not use', function () {
    // The failure that would otherwise last an hour: cache the bad document,
    // then serve it until the TTL lapses.
    [$resolver, $cache] = resolverServing([
        jwksJson(['keys' => []]),
        jwksJson(RsaKeyPair::shared()->jwks()),
    ]);

    expect(fn () => $resolver->keys(ProviderFactory::JWKS_URI))->toThrow(JwksUnavailable::class);

    expect($cache->get('nhs-login.jwks.'.sha1(ProviderFactory::JWKS_URI)))->toBeNull();

    // The next attempt reaches the network again and succeeds.
    expect($resolver->keys(ProviderFactory::JWKS_URI))->toHaveKey(RsaKeyPair::shared()->kid);
});

it('does not let a bad refresh replace a good cached key set', function () {
    [$resolver, $cache] = resolverServing([
        jwksJson(RsaKeyPair::shared()->jwks()),
        jwksJson(['keys' => []]),
    ]);

    $resolver->keys(ProviderFactory::JWKS_URI);

    expect(fn () => $resolver->refresh(ProviderFactory::JWKS_URI))->toThrow(JwksUnavailable::class);

    // The good keys are still there to serve the logins that follow.
    expect($resolver->keys(ProviderFactory::JWKS_URI))->toHaveKey(RsaKeyPair::shared()->kid)
        ->and($cache->get('nhs-login.jwks.'.sha1(ProviderFactory::JWKS_URI)))->not->toBeNull();
});

it('accepts a key that omits the optional alg member', function () {
    // "alg" is optional per RFC 7517, and parseKeySet refuses a key without one
    // unless a default is supplied. NHS login publishing such a key should not
    // be an outage.
    $jwks = RsaKeyPair::shared()->jwks();
    unset($jwks['keys'][0]['alg']);

    [$resolver] = resolverServing([jwksJson($jwks)]);

    expect($resolver->keys(ProviderFactory::JWKS_URI))->toHaveKey(RsaKeyPair::shared()->kid);
});
