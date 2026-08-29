# Changelog

All notable changes to `laravel-nhs-login` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 29-08-2026

### Added

- Socialite driver `nhslogin` with `private_key_jwt` client authentication.
- RS512 ID token verification: signature against cached JWKS, issuer, audience, nonce and expiry.
- Vectors of Trust support, including `vtr()` and `requireVerifiedIdentity()`.
- `NhsLoginUser` exposing `nhsNumber()`, `identityProofingLevel()`, `vectorOfTrust()`,
  `birthdate()` and the GP linkage claims.
- `requireIdentityLevel()`, throwing `IdentityLevelNotMet` for step-up journeys.
- Sandpit, integration and production environments resolved from a single config value.
- Automatic JWKS re-fetch when a token names an unknown key, so a key rotation at NHS login
  does not become an outage lasting until the cache expires. Rate limited by
  `jwks_refresh_cooldown`.
- `AuthorisationFailed`, distinguishing an abandoned login (`wasCancelled()`) from a real error,
  instead of posting the absent code and surfacing an HTTP failure.
- `TokenRequestFailed`, carrying the `error` and `error_description` the token endpoint returned
  rather than leaving them in a truncated Guzzle message.
- `landlineNumber()`, `landlineNumberVerified()`, `phoneNumberVerified()` and `authenticatedAt()`
  on `NhsLoginUser`, plus `claim()` for structured claims such as `delegations`.
- `NHS_LOGIN_ISSUER` for pointing a development environment at a local mock.
- A mock NHS login issuer for local development: discovery, JWKS, an authorisation picker, token
  and userinfo endpoints. It verifies the client assertion against the public half of the
  configured private key, enforces single-use codes and exact `redirect_uri` matching, and refuses
  to boot outside `local` and `testing`.
- The `sub` of the userinfo response is checked against the verified ID token, as OIDC Core 5.3.2
  requires. Previously a substituted access token could pair a verified identity for one patient
  with an NHS number for another.
- Claims are read from the signed ID token first and the userinfo response second. The precedence
  was the other way round, so `nhsNumber()`, `vot` and `identity_proofing_level` — the values
  `requireIdentityLevel()` gates on — came from an unsigned HTTP body.
- Mock issuer endpoints are gated by middleware on every request, not only at boot. Boot-time
  guards do not survive `route:cache`, which would otherwise ship the endpoints to production.
- A malformed or empty JWKS is reported as `JwksUnavailable` instead of a raw SPL exception, and
  is never written to the cache — one bad response no longer becomes an outage lasting the TTL.
- JWKS parsing supplies a default algorithm, so a key omitting the optional `alg` member does not
  fail every login.
- The mock's route prefix falls back to a default, so a published config that omits it cannot
  mount the issuer at the application root.
- The provider follows the container's `request` rebinding, so a cached driver on a long-lived
  worker (Octane, Swoole, RoadRunner) cannot serve a later request while holding an earlier one's
  session — which could make a stale state comparison pass.
- userinfo failures raise `UserInfoRequestFailed` instead of a raw Guzzle or JSON exception.
- `identityProofingLevel()` fails closed to `P0` on an unrecognised Vector of Trust instead of
  throwing out of `isIdentityVerified()`.
- Stateless mode is usable: `getNonce()` exposes the value `redirect()` generated, and the failure
  message says what to do rather than naming a session that does not exist.
- The ID token must carry an expiry, and `azp` must name this client when several audiences are
  listed.
- `vtr()` parses each vector on the way in, so a typo fails locally rather than at NHS login.
- The client assertion no longer sets `kid` twice, and an empty configured key id means no `kid`.
- Driver registration no longer depends on `$this` inside the callback given to
  `Manager::extend()`, which Laravel rebinds to the manager — `Socialite::driver('nhslogin')`
  failed on the first real call without it.
- ID token leeway is restored after decoding, so it never leaks into other code decoding JWTs.
- The `*_verified` claims are read as booleans, so the string `"false"` does not read as true.
- `refreshToken()`, redeeming a refresh token the way every other call to the token endpoint
  authenticates: `private_key_jwt`, never the client secret Socialite's own implementation posts.
  Verifies a returned ID token the same way the original login's was, including an optional check
  that the subject has not changed.
- `NhsLoginAuthenticated` and `NhsLoginAuthenticationFailed`, dispatched on every `user()` call, so
  the audit trail clinical services are expected to keep (DCB0129, DSPT) does not depend on every
  application building its own.
- Static analysis raised from PHPStan level 6 to level 8.
- A `coverage` CI job, uploading a Clover report as a build artifact. Not gated on a `--min`
  threshold yet — see the workflow file for why guessing one is worse than not having it.
- README documents that NHS login publishes no `end_session_endpoint`: there is no RP-initiated
  logout to call, and no "log out" button can honestly promise one.
