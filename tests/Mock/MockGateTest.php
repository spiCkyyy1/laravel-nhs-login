<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Tests\MockFlow;

/**
 * The boot-time guards do not survive `route:cache`: the routes are compiled
 * while the mock is enabled and production loads the compiled file without
 * booting anything that could refuse.
 *
 * These tests reproduce that state directly — the routes are registered, and
 * the configuration says they should not answer.
 */
it('refuses every endpoint when the mock is switched off at request time', function () {
    config()->set('nhs-login.mock.enabled', false);

    $this->get(MockFlow::PREFIX.'/.well-known/jwks.json')->assertNotFound();
    $this->get(MockFlow::PREFIX.'/.well-known/openid-configuration')->assertNotFound();
    $this->get(MockFlow::PREFIX.'/authorize')->assertNotFound();
    $this->post(MockFlow::PREFIX.'/authorize')->assertNotFound();
    $this->post(MockFlow::PREFIX.'/token')->assertNotFound();
    $this->get(MockFlow::PREFIX.'/userinfo')->assertNotFound();
});

it('refuses every endpoint outside local and testing', function () {
    $this->app['env'] = 'production';

    $this->get(MockFlow::PREFIX.'/.well-known/jwks.json')->assertNotFound();
    $this->post(MockFlow::PREFIX.'/token')->assertNotFound();
});

it('answers 404 rather than 403, so it does not advertise itself', function () {
    // A 403 would tell an attacker the endpoint exists and is merely disabled.
    config()->set('nhs-login.mock.enabled', false);

    $this->get(MockFlow::PREFIX.'/.well-known/jwks.json')->assertStatus(404);
});

it('does not issue an authorisation code once switched off', function () {
    // The endpoint that mattered: it hands out codes for any NHS number
    // without authenticating the caller.
    config()->set('nhs-login.mock.enabled', false);

    $this->post(MockFlow::PREFIX.'/authorize', [
        'action' => 'approve',
        'client_id' => 'test-client',
        'redirect_uri' => MockFlow::CALLBACK,
        'vector' => 'P9.Cp.Cd',
    ])->assertNotFound();
});

it('still answers normally while it is switched on', function () {
    $this->get(MockFlow::PREFIX.'/.well-known/jwks.json')->assertOk();
});
