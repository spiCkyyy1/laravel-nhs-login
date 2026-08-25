<?php

declare(strict_types=1);

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Spickyyy1\NhsLogin\ClientAssertion;
use Spickyyy1\NhsLogin\Support\Environment;
use Spickyyy1\NhsLogin\Tests\MockFlow;
use Spickyyy1\NhsLogin\Tests\RsaKeyPair;

it('publishes a discovery document and a key set', function () {
    $this->get(MockFlow::PREFIX.'/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'http://localhost/nhs-login-mock')
        ->assertJsonPath('token_endpoint_auth_methods_supported', ['private_key_jwt'])
        ->assertJsonPath('id_token_signing_alg_values_supported', ['RS512']);

    $this->get(MockFlow::PREFIX.'/.well-known/jwks.json')
        ->assertOk()
        ->assertJsonPath('keys.0.kty', 'RSA')
        ->assertJsonPath('keys.0.alg', 'RS512');
});

it('shows the requested vectors on the picker', function () {
    $this->get(MockFlow::PREFIX.'/authorize?'.http_build_query(MockFlow::authorizeQuery()))
        ->assertOk()
        ->assertSee('P9.Cp.Cd — requested')
        ->assertSee('P5.Cm')
        ->assertSee('not NHS login');
});

it('refuses a redirect_uri that was not registered', function () {
    // Redirecting the error back to an unvalidated URI would make this an
    // open redirect, so it has to be refused in place.
    $this->get(MockFlow::PREFIX.'/authorize?'.http_build_query(MockFlow::authorizeQuery([
        'redirect_uri' => 'https://evil.test/steal',
    ])))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

it('sends the user back with an error when they cancel', function () {
    $response = $this->post(MockFlow::PREFIX.'/authorize', [
        'action' => 'cancel',
        'redirect_uri' => MockFlow::CALLBACK,
        'state' => 'st4te',
    ]);

    $response->assertRedirect();

    parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

    expect($query['error'])->toBe('access_denied')
        ->and($query['state'])->toBe('st4te');
});

it('issues an ID token that verifies against its own key set', function () {
    $tokens = MockFlow::exchange((string) MockFlow::approve());

    $keys = JWK::parseKeySet($this->get(MockFlow::PREFIX.'/.well-known/jwks.json')->json());
    $claims = (array) JWT::decode($tokens['id_token'], $keys);

    expect($claims['iss'])->toBe('http://localhost/nhs-login-mock')
        ->and($claims['aud'])->toBe('test-client')
        ->and($claims['nonce'])->toBe('test-nonce')
        ->and($claims['vot'])->toBe('P9.Cp.Cd')
        ->and($claims['nhs_number'])->toBe('9912003888')
        ->and($tokens['token_type'])->toBe('Bearer');
});

it('rejects a token request that is not signed with the configured key', function () {
    // The whole point of the mock: a key that fails here is a key that would
    // have failed at NHS login.
    $stranger = new ClientAssertion(
        clientId: 'test-client',
        privateKey: RsaKeyPair::generate('other')->privateKey(),
    );

    $code = (string) MockFlow::approve();

    $this->post(MockFlow::PREFIX.'/token', [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => MockFlow::CALLBACK,
        'client_id' => 'test-client',
        'client_assertion_type' => ClientAssertion::TYPE,
        'client_assertion' => $stranger->create(app(Environment::class)->tokenEndpoint()),
    ])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('rejects a token request with no assertion at all', function () {
    $this->post(MockFlow::PREFIX.'/token', [
        'grant_type' => 'authorization_code',
        'code' => (string) MockFlow::approve(),
        'redirect_uri' => MockFlow::CALLBACK,
    ])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('will not let an authorisation code be used twice', function () {
    $code = (string) MockFlow::approve();

    MockFlow::exchange($code);

    expect(MockFlow::exchange($code)['error'])->toBe('invalid_grant');
});

it('serves userinfo only to the token it issued', function () {
    $tokens = MockFlow::exchange((string) MockFlow::approve());

    $this->get(MockFlow::PREFIX.'/userinfo', ['Authorization' => 'Bearer '.$tokens['access_token']])
        ->assertOk()
        ->assertJsonPath('nhs_number', '9912003888')
        ->assertJsonPath('given_name', 'Aisha');

    $this->get(MockFlow::PREFIX.'/userinfo', ['Authorization' => 'Bearer not-a-real-token'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

it('returns no NHS number for an unverified user', function () {
    $tokens = MockFlow::exchange((string) MockFlow::approve(['vector' => 'P0.Cp']));

    $claims = $this->get(MockFlow::PREFIX.'/userinfo', [
        'Authorization' => 'Bearer '.$tokens['access_token'],
    ])->json();

    expect($claims)->not->toHaveKey('nhs_number')
        ->and($claims)->not->toHaveKey('birthdate')
        ->and($claims['identity_proofing_level'])->toBe('P0');
});

it('honours the claims typed into the picker', function () {
    $tokens = MockFlow::exchange((string) MockFlow::approve([
        'claims' => ['nhs_number' => '9000000009', 'given_name' => 'Test', 'family_name' => 'Patient'],
    ]));

    $claims = $this->get(MockFlow::PREFIX.'/userinfo', [
        'Authorization' => 'Bearer '.$tokens['access_token'],
    ])->json();

    expect($claims['nhs_number'])->toBe('9000000009')
        ->and($claims['given_name'])->toBe('Test');
});
