<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Carbon;
use Spickyyy1\NhsLogin\JwksResolver;
use Spickyyy1\NhsLogin\Tests\ProviderFactory;
use Spickyyy1\NhsLogin\Tests\RsaKeyPair;

/**
 * @return array{0: JwksResolver, 1: ArrayObject}
 */
function countingResolver(int $cooldown = 60): array
{
    /** @var ArrayObject<int, bool> $fetches */
    $fetches = new ArrayObject;
    $keys = RsaKeyPair::shared();

    $handler = static function () use ($fetches, $keys) {
        $fetches[] = true;

        return Create::promiseFor(new Response(
            200,
            ['Content-Type' => 'application/json'],
            json_encode($keys->jwks(), JSON_THROW_ON_ERROR),
        ));
    };

    $resolver = new JwksResolver(
        new Client(['handler' => HandlerStack::create($handler)]),
        new Repository(new ArrayStore),
        3600,
        $cooldown,
    );

    return [$resolver, $fetches];
}

it('fetches the key set once and serves the rest from cache', function () {
    [$resolver, $fetches] = countingResolver();

    $resolver->keys(ProviderFactory::JWKS_URI);
    $resolver->keys(ProviderFactory::JWKS_URI);
    $resolver->keys(ProviderFactory::JWKS_URI);

    expect($fetches->count())->toBe(1);
});

it('bypasses the cache on refresh', function () {
    [$resolver, $fetches] = countingResolver();

    $resolver->keys(ProviderFactory::JWKS_URI);
    $resolver->refresh(ProviderFactory::JWKS_URI);

    expect($fetches->count())->toBe(2);

    Carbon::setTestNow();
});

it('rate limits refreshes so a forged key id cannot become a flood', function () {
    // Anyone can send a token naming a key that does not exist. Without the
    // cooldown, each one would become an outbound request to NHS login.
    [$resolver, $fetches] = countingResolver();

    $resolver->keys(ProviderFactory::JWKS_URI);

    foreach (range(1, 50) as $ignored) {
        $resolver->refresh(ProviderFactory::JWKS_URI);
    }

    expect($fetches->count())->toBe(2);
});

it('serves the refreshed keys while the cooldown holds', function () {
    [$resolver, $fetches] = countingResolver();

    $first = $resolver->refresh(ProviderFactory::JWKS_URI);
    $second = $resolver->refresh(ProviderFactory::JWKS_URI);

    expect(array_keys($second))->toBe(array_keys($first))
        ->and($fetches->count())->toBe(1);
});

it('allows an immediate refresh once the key set is forgotten', function () {
    [$resolver, $fetches] = countingResolver();

    $resolver->refresh(ProviderFactory::JWKS_URI);
    $resolver->forget(ProviderFactory::JWKS_URI);
    $resolver->refresh(ProviderFactory::JWKS_URI);

    expect($fetches->count())->toBe(2);
});

it('honours a zero cooldown for anyone who wants the old behaviour', function () {
    [$resolver, $fetches] = countingResolver(cooldown: 0);

    $resolver->refresh(ProviderFactory::JWKS_URI);
    $resolver->refresh(ProviderFactory::JWKS_URI);

    expect($fetches->count())->toBe(2);
});

it('allows a refresh again once the cooldown has lapsed', function () {
    // A rate limit that never released would look identical to the test above,
    // and would permanently block the key rotation it exists to allow.
    [$resolver, $fetches] = countingResolver(cooldown: 60);

    $resolver->refresh(ProviderFactory::JWKS_URI);
    $resolver->refresh(ProviderFactory::JWKS_URI);

    expect($fetches->count())->toBe(1);

    // Carbon rather than $this->travel(): the cache store reads the clock
    // through Carbon, and this says so without depending on the test case.
    Carbon::setTestNow(Carbon::now()->addSeconds(61));

    $resolver->refresh(ProviderFactory::JWKS_URI);

    expect($fetches->count())->toBe(2);
});
