<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Environment
    |--------------------------------------------------------------------------
    |
    | Which NHS login environment to talk to. Every endpoint is derived from
    | the issuer, so this single value is what separates sandpit from live —
    | there is deliberately no other switch to set wrong.
    |
    */

    'environment' => env('NHS_LOGIN_ENVIRONMENT', 'sandpit'),

    // Overrides the issuer map below entirely. For pointing at a local mock
    // during development — never set this in production.
    'issuer' => env('NHS_LOGIN_ISSUER'),

    'issuers' => [
        'sandpit' => 'https://auth.sandpit.signin.nhs.uk',
        'integration' => 'https://auth.aos.signin.nhs.uk',
        'production' => 'https://auth.login.nhs.uk',
    ],

    /*
    |--------------------------------------------------------------------------
    | Client credentials
    |--------------------------------------------------------------------------
    |
    | NHS login only supports private_key_jwt client authentication, so there
    | is no client secret. You register a JWKS endpoint with NHS login and
    | sign a client assertion with the matching private key.
    |
    */

    'client_id' => env('NHS_LOGIN_CLIENT_ID'),

    'redirect' => env('NHS_LOGIN_REDIRECT_URI'),

    'private_key' => env('NHS_LOGIN_PRIVATE_KEY'),

    'private_key_path' => env('NHS_LOGIN_PRIVATE_KEY_PATH'),

    'private_key_passphrase' => env('NHS_LOGIN_PRIVATE_KEY_PASSPHRASE'),

    // The "kid" of the public key published on your JWKS endpoint. Required
    // once you rotate keys, since NHS login needs to know which to verify with.
    'key_id' => env('NHS_LOGIN_KEY_ID'),

    /*
    |--------------------------------------------------------------------------
    | Defaults for the authorisation request
    |--------------------------------------------------------------------------
    |
    | Vectors of Trust are ORed together; components within a vector are ANDed.
    | Omitting vtr entirely makes NHS login default to P9, which forces full
    | identity verification on every user — usually not what you want.
    |
    */

    'scopes' => ['openid', 'profile'],

    'vtr' => ['P9.Cp.Cd', 'P9.Cm'],

    /*
    |--------------------------------------------------------------------------
    | Token handling
    |--------------------------------------------------------------------------
    */

    // Lifetime of the signed client assertion, in seconds.
    'assertion_ttl' => 300,

    // Clock skew tolerated when validating the ID token, in seconds.
    'leeway' => 30,

    // How long to cache NHS login's public keys. They rotate rarely, but a
    // rotation mid-cache would reject valid tokens until this expires.
    'jwks_ttl' => 3600,

    'jwks_cache_store' => env('NHS_LOGIN_JWKS_CACHE_STORE'),

    // A token naming a key we do not hold triggers one re-fetch, in case NHS
    // login rotated early. This is the shortest gap between two such
    // re-fetches: without it, forged key IDs would become a way to make this
    // application hammer NHS login.
    'jwks_refresh_cooldown' => 60,

    /*
    |--------------------------------------------------------------------------
    | HTTP
    |--------------------------------------------------------------------------
    */

    'timeout' => 10,

    /*
    |--------------------------------------------------------------------------
    | Mock issuer
    |--------------------------------------------------------------------------
    |
    | NHS login has no self-service sandbox, so this serves the other half of
    | the protocol locally: a real key pair, real RS512 tokens, and a real
    | check of your client assertion. It refuses to start anywhere but local
    | and testing — it mints valid ID tokens for any NHS number you type.
    |
    | Enable it, then point the client at it:
    |
    |     NHS_LOGIN_MOCK=true
    |     NHS_LOGIN_ISSUER="\${APP_URL}/nhs-login-mock"
    |
    */

    'mock' => [
        'enabled' => env('NHS_LOGIN_MOCK', false),
        'prefix' => env('NHS_LOGIN_MOCK_PREFIX', 'nhs-login-mock'),
        // Deliberately empty: the token endpoint is called server to server,
        // and CSRF protection would reject it. The mock is unauthenticated by
        // design and only ever mounts in local or testing.
        'middleware' => [],
    ],

];
