<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Tests\MockFlow;

/**
 * The checks are the mock's whole reason to exist: one that waved requests
 * through would let a broken integration look healthy right up until it met
 * the sandpit.
 */
it('refuses an unknown client on the authorisation request', function () {
    $response = $this->get(MockFlow::PREFIX.'/authorize?'.http_build_query(MockFlow::authorizeQuery([
        'client_id' => 'not-our-client',
    ])));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('error=unauthorized_client');
});

it('refuses a response_type other than code', function () {
    $response = $this->get(MockFlow::PREFIX.'/authorize?'.http_build_query(MockFlow::authorizeQuery([
        'response_type' => 'token',
    ])));

    expect($response->headers->get('Location'))->toContain('error=unsupported_response_type');
});

it('requires the openid scope', function () {
    $response = $this->get(MockFlow::PREFIX.'/authorize?'.http_build_query(MockFlow::authorizeQuery([
        'scope' => 'profile',
    ])));

    expect($response->headers->get('Location'))->toContain('error=invalid_scope');
});

it('refuses a redirect_uri that was not registered when approving', function () {
    // The GET is covered elsewhere; the POST carries hidden fields the caller
    // controls just as freely.
    $this->post(MockFlow::PREFIX.'/authorize', [
        'action' => 'approve',
        'client_id' => 'test-client',
        'redirect_uri' => 'https://evil.test/steal',
        'vector' => 'P9.Cp.Cd',
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

it('refuses an unknown client when approving', function () {
    $response = $this->post(MockFlow::PREFIX.'/authorize', [
        'action' => 'approve',
        'client_id' => 'not-our-client',
        'redirect_uri' => MockFlow::CALLBACK,
        'vector' => 'P9.Cp.Cd',
    ]);

    expect($response->headers->get('Location'))->toContain('error=unauthorized_client');
});

it('refuses a Vector of Trust it cannot parse', function () {
    $response = $this->post(MockFlow::PREFIX.'/authorize', [
        'action' => 'approve',
        'client_id' => 'test-client',
        'redirect_uri' => MockFlow::CALLBACK,
        'vector' => 'P9.Cx',
    ]);

    expect($response->headers->get('Location'))->toContain('error=invalid_request');
});

it('refuses a grant type other than authorization_code', function () {
    expect(MockFlow::exchange((string) MockFlow::approve(), ['grant_type' => 'client_credentials'])['error'])
        ->toBe('invalid_request');
});

it('refuses a token request whose redirect_uri does not match the code', function () {
    expect(MockFlow::exchange((string) MockFlow::approve(), ['redirect_uri' => 'https://elsewhere.test/cb'])['error'])
        ->toBe('invalid_grant');
});

it('refuses userinfo with no Authorization header', function () {
    $this->get(MockFlow::PREFIX.'/userinfo')
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

it('survives a vtr parameter that is not valid JSON', function () {
    // Renders the picker rather than erroring: the tester has typed something
    // wrong, and telling them so beats a stack trace.
    $this->get(MockFlow::PREFIX.'/authorize?'.http_build_query(MockFlow::authorizeQuery([
        'vtr' => 'not-json',
    ])))->assertOk();
});
