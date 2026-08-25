<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Tests\ProviderFactory;

function queryFrom(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    return $query;
}

it('builds an authorisation URL against the configured environment', function () {
    $factory = ProviderFactory::make();

    $url = $factory->provider->redirect()->getTargetUrl();

    expect($url)->toStartWith('https://auth.sandpit.signin.nhs.uk/authorize?');

    $query = queryFrom($url);

    expect($query['client_id'])->toBe(ProviderFactory::CLIENT_ID)
        ->and($query['redirect_uri'])->toBe(ProviderFactory::REDIRECT)
        ->and($query['response_type'])->toBe('code')
        ->and($query['state'])->not->toBeEmpty();
});

it('always sends a nonce and remembers it for verification', function () {
    $factory = ProviderFactory::make();

    $query = queryFrom($factory->provider->redirect()->getTargetUrl());

    expect($query['nonce'])->not->toBeEmpty()
        ->and($factory->request->session()->get('nhs_login.nonce'))->toBe($query['nonce']);
});

it('sends vectors of trust as a JSON array', function () {
    $factory = ProviderFactory::make();

    $factory->provider->vtr(['P9.Cp.Cd', 'P9.Cm']);

    $query = queryFrom($factory->provider->redirect()->getTargetUrl());

    expect($query['vtr'])->toBe('["P9.Cp.Cd","P9.Cm"]');
});

it('omits vtr entirely when none is set', function () {
    $factory = ProviderFactory::make();

    $query = queryFrom($factory->provider->redirect()->getTargetUrl());

    expect($query)->not->toHaveKey('vtr');
});

it('requests P5 when only a verified identity is needed', function () {
    $factory = ProviderFactory::make();

    $factory->provider->requireVerifiedIdentity();

    $query = queryFrom($factory->provider->redirect()->getTargetUrl());

    expect($query['vtr'])->toBe('["P5.Cp.Cd","P5.Cm"]');
});

it('space-separates scopes as OIDC requires', function () {
    $factory = ProviderFactory::make();

    $factory->provider->setScopes(['openid', 'profile', 'email']);

    $query = queryFrom($factory->provider->redirect()->getTargetUrl());

    expect($query['scope'])->toBe('openid profile email');
});
