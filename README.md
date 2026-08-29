# NHS login for Laravel

[![Tests](https://github.com/spiCkyyy1/laravel-nhs-login/actions/workflows/tests.yml/badge.svg)](https://github.com/spiCkyyy1/laravel-nhs-login/actions/workflows/tests.yml)
[![Latest Version](https://img.shields.io/packagist/v/spickyyy1/laravel-nhs-login.svg)](https://packagist.org/packages/spickyyy1/laravel-nhs-login)
[![Downloads](https://img.shields.io/packagist/dt/spickyyy1/laravel-nhs-login.svg)](https://packagist.org/packages/spickyyy1/laravel-nhs-login)

Sign users in with [NHS login](https://digital.nhs.uk/services/nhs-login) from a Laravel app.

NHS login is OpenID Connect, but it is not a drop-in Socialite provider. It accepts **only**
`private_key_jwt` client authentication — there is no client secret to post — and the ID token,
signed with RS512, is the actual proof of identity. This package handles both, plus Vectors of
Trust and the NHS-specific claims.

```php
$user = Socialite::driver('nhslogin')->user();

$user->nhsNumber();               // "9912003888", or null for an unverified P0 user
$user->identityProofingLevel();   // IdentityProofingLevel::P9
$user->isIdentityVerified();      // true
$user->birthdate();               // Carbon instance
```

## Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Routes](#routes)
- [Identity levels and Vectors of Trust](#identity-levels-and-vectors-of-trust)
- [Scopes](#scopes)
- [Stateless use](#stateless-use)
- [Claims](#claims)
- [Refreshing a session](#refreshing-a-session)
- [Audit events](#audit-events)
- [What gets verified](#what-gets-verified)
- [Handling failures](#handling-failures)
- [Security notes](#security-notes)
- [Local development](#local-development)
- [Testing](#testing)
- [Compatibility](#compatibility)

## Installation

```bash
composer require spickyyy1/laravel-nhs-login
```

Requires PHP 8.2+ and Laravel 11, 12 or 13. See [Compatibility](#compatibility) for the Socialite
version note if you're on Laravel 13.

Publish the config if you want to change the defaults:

```bash
php artisan vendor:publish --tag=nhs-login-config
```

## Configuration

NHS login has no client secret. You generate an RSA key pair, publish the public half on a JWKS
endpoint that you register with NHS login, and this package signs a client assertion with the
private half on every token request.

```dotenv
NHS_LOGIN_ENVIRONMENT=sandpit          # sandpit | integration | production
NHS_LOGIN_CLIENT_ID=your-client-id
NHS_LOGIN_REDIRECT_URI=https://your-app.test/auth/nhs/callback
NHS_LOGIN_PRIVATE_KEY_PATH=/run/secrets/nhs-login-signing-key.pem
NHS_LOGIN_KEY_ID=the-kid-on-your-jwks-endpoint
```

Every endpoint is derived from the environment, so that one variable is what separates sandpit
from live. There is deliberately no second switch to get wrong.

| Environment   | Issuer                                  |
| ------------- | --------------------------------------- |
| `sandpit`     | `https://auth.sandpit.signin.nhs.uk`    |
| `integration` | `https://auth.aos.signin.nhs.uk`        |
| `production`  | `https://auth.login.nhs.uk`             |

If your key arrives as an environment variable rather than a file, set `NHS_LOGIN_PRIVATE_KEY`
to the PEM contents instead (escaped `\n` newlines are handled).

`NHS_LOGIN_ISSUER` overrides the table entirely, for pointing at a local mock during development.
Never set it in production.

## Routes

```php
Route::get('/auth/nhs', fn () => Socialite::driver('nhslogin')->redirect());

Route::get('/auth/nhs/callback', function () {
    $nhsUser = Socialite::driver('nhslogin')
        ->user()
        ->requireIdentityLevel(IdentityProofingLevel::P5);

    $user = User::updateOrCreate(
        ['nhs_login_sub' => $nhsUser->getId()],
        ['nhs_number' => $nhsUser->nhsNumber(), 'name' => $nhsUser->getName()],
    );

    Auth::login($user);

    return redirect()->intended();
});
```

Key the local account on `sub`, never on the NHS number — `sub` is stable and always present,
while an unverified user has no NHS number at all.

## Identity levels and Vectors of Trust

NHS login describes how strongly an identity was proven with a Vector of Trust such as
`P9.Cp.Cd`. The identity component is what usually matters:

| Level | Meaning                                                             | NHS number? |
| ----- | ------------------------------------------------------------------- | ----------- |
| `P0`  | Email address and mobile number verified                              | No          |
| `P5`  | Matched to a Personal Demographics Service record                     | Yes         |
| `P9`  | Photographic identity verified against the person                     | Yes         |

Request what your service actually needs. **Omitting `vtr` entirely makes NHS login default to
P9**, forcing every user through full identity verification:

```php
// Enough to get an NHS number, without demanding photo ID
Socialite::driver('nhslogin')->requireVerifiedIdentity()->redirect();

// Or set the vectors yourself — vectors are ORed, components within one ANDed
Socialite::driver('nhslogin')->vtr(['P9.Cp.Cd', 'P9.Cm'])->redirect();
```

When a session comes back below the level you need, `requireIdentityLevel()` throws
`IdentityLevelNotMet`. Catch it and send the user back through with a higher `vtr` to trigger
NHS login's step-up journey, rather than treating it as a failed login.

## Scopes

The scopes NHS login publishes are available as an enum. Requesting one you were not granted at
registration fails the authorisation request, so ask only for what you need.

```php
Socialite::driver('nhslogin')
    ->setScopes([Scope::OpenId->value, Scope::Profile->value, Scope::Email->value])
    ->redirect();
```

## Stateless use

For an API or SPA callback with no session, the nonce has to be carried by you — there is nowhere
else to put it:

```php
$provider = Socialite::driver('nhslogin')->stateless();
$url = $provider->redirect()->getTargetUrl();

$nonce = $provider->getNonce();   // persist this against the pending login
```

Then hand it back on the callback, to what is a different instance:

```php
$user = Socialite::driver('nhslogin')->stateless()->nonce($nonce)->user();
```

Without it the ID token cannot be checked against anything, and the login is refused.

## Claims

Typed accessors cover the scalar claims: `nhsNumber()`, `birthdate()`, `givenName()`,
`familyName()`, `phoneNumber()`, `phoneNumberVerified()`, `landlineNumber()`,
`landlineNumberVerified()`, `emailVerified()`, `authenticatedAt()`, and the GP linkage trio
`gpOdsCode()` / `gpUserId()` / `gpLinkageKey()`.

`identityProofingLevel()` never throws and fails closed: an unfamiliar vector — NHS login already
reserves `Ck` for a credential it has not shipped — reads as `P0`, not as an exception taking the
login with it. `vectorOfTrust()` is strict by contrast, because a caller asking for the raw vector
wants to know when it cannot be parsed.

`authenticatedAt()` is when NHS login authenticated the user, not when your session began — an
existing NHS login session is reused, so it can be hours old. Check it before anything that
warrants a recent authentication.

Structured claims — `delegations`, `client_user_metadata` — have no accessor yet and are reached
with `claim()`:

```php
$nhsUser->claim('delegations');
```

## Refreshing a session

NHS login's token endpoint issues a refresh token alongside the access and ID token. Redeem one
with `refreshToken()`, which authenticates the same way as everything else in this package —
there is still no client secret to post:

```php
$token = Socialite::driver('nhslogin')->refreshToken($user->refreshToken, $user->getId());

$token->token;          // the new access token
$token->refreshToken;   // persist this — NHS login may or may not rotate it on use
$token->idTokenClaims;  // null unless NHS login returned a new ID token
```

The second argument is optional but worth passing when you have it — typically the `sub` the
local account is keyed on. NHS login is not obliged to return a new ID token on a refresh; when it
does, it is verified the same way the original one was, and passing the expected subject catches a
token that has been swapped in for someone else. When it does not, `idTokenClaims` is `null`: a
refresh proves the session is still live, not anything new about identity, so nothing about the
user has to be — or can be — re-checked.

## Audit events

`NhsLoginAuthenticated` and `NhsLoginAuthenticationFailed` are dispatched on every call to
`user()`, so an audit trail (DCB0129, DSPT) doesn't depend on every application remembering to
build one:

```php
Event::listen(function (NhsLoginAuthenticated $event) {
    Log::info('NHS login succeeded', [
        'subject' => $event->subject,
        'level' => $event->identityProofingLevel->value,
    ]);
});

Event::listen(function (NhsLoginAuthenticationFailed $event) {
    Log::info('NHS login attempt failed', ['exception' => $event->exception::class]);
});
```

`NhsLoginAuthenticationFailed` fires for a cancelled login too — check
`$event->exception instanceof AuthorisationFailed && $event->exception->wasCancelled()` before
treating it as something worth alerting on, for the same reason `wasCancelled()` exists at all.
Both events carry safe, already-sanitised data by design; see their docblocks before logging
anything beyond what they expose.

## What gets verified

Every login verifies the ID token before building a user:

- the RS512 signature, against NHS login's published JWKS (cached, TTL configurable)
- the issuer matches the configured environment
- the audience is your client ID
- the nonce matches the one stored when the flow started
- expiry, within a configurable leeway for clock skew

The userinfo response is then fetched and its `sub` must match the one in the verified ID token,
as OIDC requires. The access token and the ID token are separate credentials, and nothing in the
token response ties them to the same person; without that check, a substituted access token would
yield a verified identity for one patient and an NHS number for another.

Any failure throws `InvalidIdToken` and the session is abandoned.

**Where the two sources disagree, the ID token wins.** It is signed and has been verified; the
userinfo response is an HTTP body. Claims that identity decisions rest on — `nhs_number`, `vot`,
`identity_proofing_level` — are read from the ID token first, with userinfo filling only the gaps
left by the scopes you were granted.

NHS login rotates its signing keys without announcing it. When a token names a key that is not in
the cached set, the key set is re-fetched once and verification retried, so a rotation does not
become an outage lasting until the cache expires. That re-fetch is rate limited
(`jwks_refresh_cooldown`, 60s) because the key ID in a token is attacker-controlled and would
otherwise be a way to make your application hammer NHS login.

## Handling failures

| Exception | When | What to do |
| --- | --- | --- |
| `AuthorisationFailed` | Came back without a code | Check `wasCancelled()` — `access_denied` means the user changed their mind. Redirect quietly. |
| `UserInfoRequestFailed` | The profile lookup failed after the identity was established | A 401 usually means the access token expired between the two calls. Retry the login. |
| `TokenRequestFailed` | The token endpoint said no | Read `$e->error`. `invalid_client` means your assertion did not verify against the key NHS login holds; `invalid_grant` usually means a `redirect_uri` mismatch. |
| `InvalidIdToken` | The token could not be trusted, or userinfo described someone else | Abandon the session. Never fall through to the userinfo response. |
| `JwksUnavailable` | NHS login's signing keys could not be fetched or parsed | Upstream problem, not a bad user. Retry; do not treat it as a failed login. |
| `IdentityLevelNotMet` | Authenticated, but not proven enough | Send them back with a higher `vtr` for a step-up journey. |
| `NhsLoginConfigurationException` | Misconfigured | Thrown at resolve time, not mid-login. |

```php
try {
    $nhsUser = Socialite::driver('nhslogin')->user();
} catch (AuthorisationFailed $e) {
    return $e->wasCancelled()
        ? redirect('/')->with('status', 'Sign in cancelled.')
        : redirect('/login')->withErrors(__('Sign in with NHS login failed.'));
}
```

A cancelled login is the common case, not an edge case — users tap back. Reporting it as an error
trains people to distrust the button.

## Security notes

- Never log the ID token, the access token, or the claims. They carry an NHS number, a date of
  birth, and a name.
- Keep the signing key out of the repository and out of `config/`. Mount it or inject it.
- Rotate keys by publishing both on your JWKS endpoint, switching `NHS_LOGIN_KEY_ID`, then
  retiring the old one.
- Error details from the callback are sanitised before they reach an exception message: they are
  query parameters, so anyone who can send a user to your callback URL controls them.
- NHS login's discovery document publishes no `end_session_endpoint`, so there is no RP-initiated
  logout to call — logging a user out of your application does not, and cannot, log them out of
  NHS login. Do not build a "log out" button that promises otherwise.

## Local development

NHS login has no self-service sandbox — sandpit access is a form and about a day's wait. The
package ships a mock issuer so the flow can be exercised before then:

```dotenv
NHS_LOGIN_MOCK=true
NHS_LOGIN_ISSUER="${APP_URL}/nhs-login-mock"
NHS_LOGIN_CLIENT_ID=local-client
NHS_LOGIN_REDIRECT_URI="${APP_URL}/auth/nhs/callback"
NHS_LOGIN_PRIVATE_KEY_PATH=/path/to/local-key.pem
```

Generate a key for it — this is your client key, the one that would sit on your JWKS endpoint:

```bash
openssl genrsa -out storage/local-nhs-key.pem 2048
```

Then hit `/auth/nhs` and you get a picker: choose a Vector of Trust, edit the claims, sign in or
cancel. The redirect comes back to your real callback route with a real code.

**Run the server with workers.** Your callback calls the token endpoint server to server, and if
that endpoint is the same single-threaded process it will deadlock until Guzzle times out:

```bash
PHP_CLI_SERVER_WORKERS=4 php artisan serve --no-reload
```

`--no-reload` is required — without it Laravel ignores `PHP_CLI_SERVER_WORKERS` and runs one
process. Anything that already serves concurrent requests (Herd, Valet, Octane, Sail, nginx) is
fine as it is.

It is not a stub. The mock generates its own RSA key pair, publishes a JWKS endpoint, signs RS512
ID tokens, and **verifies your client assertion against the public half of your configured private
key**. A key that fails here is a key that would have failed at NHS login. Authorisation codes are
single use, `redirect_uri` must match exactly, and cancelling returns `error=access_denied` — so
the paths that are awkward to reach against a real provider are one click away.

Pick a level below the one you requested to exercise your step-up path, or `P0` to check what
happens when there is no NHS number.

### Guards

The mock signs ID tokens this application will accept, for any NHS number typed into a form. So:

- it refuses to boot unless the app environment is `local` or `testing`
- it refuses to boot if `NHS_LOGIN_ISSUER` still points at a real NHS login environment, rather
  than mounting routes nothing will ever reach while real logins fail
- it is off unless `NHS_LOGIN_MOCK` is explicitly true
- **every request to a mock endpoint re-checks both conditions** and answers 404 otherwise

The last one is not redundant. The others run at boot, and boot-time guards do not survive
`php artisan route:cache`: caching boots the application and serialises whatever routes exist at
that moment, and production then loads the compiled file without booting anything that could
refuse. Cache the routes once with the mock enabled — the state your machine is in while
developing — and the endpoints would otherwise ship.

One case the middleware cannot cover: `config:cache` run with `APP_ENV=local` freezes the
environment into the cached config, so the application believes it is local wherever it runs. That
misconfiguration turns on debug mode and much else besides; it is not specific to this package.

Its routes carry no middleware by default: the token endpoint is called server to server, and CSRF
protection would reject it.

## Testing

```bash
composer test
```

The suite generates a throwaway RSA key pair at run time and mocks NHS login's HTTP endpoints,
so nothing in this repository resembles a real signing key and no test touches the network.

## Compatibility

| Package | PHP    | Laravel      | Socialite |
| ------- | ------ | ------------ | --------- |
| `0.x`   | 8.2+   | 11, 12, 13   | 5.30+     |

On a long-lived worker — Octane, Swoole, RoadRunner — Socialite caches driver instances on a
singleton manager, so a provider built during one request would otherwise serve the next while
still holding the first request's session. The package follows the container's `request`
rebinding, the same way the framework keeps its own redirector current, so no configuration is
needed.

Socialite 5.30 still requires Guzzle `^6.0|^7.0`, while a fresh Laravel 13 app ships Guzzle 8. On
Laravel 13, installing this package will therefore ask to downgrade Guzzle to 7.x — use
`composer require spickyyy1/laravel-nhs-login -W` and expect that change. It is Socialite's
constraint, not this package's, and it will lift when Socialite widens it.

## Disclaimer

This is an independent open-source package. It is not affiliated with, endorsed by, or supported
by NHS England or NHS Digital. You are responsible for your own NHS login onboarding, your
clinical safety obligations (DCB0129), and your Data Security and Protection Toolkit assessment.
Provided as-is, without warranty.

## Licence

MIT. See [LICENSE](LICENSE).
