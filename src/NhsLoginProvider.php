<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin;

use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Spickyyy1\NhsLogin\Exceptions\AuthorisationFailed;
use Spickyyy1\NhsLogin\Exceptions\InvalidIdToken;
use Spickyyy1\NhsLogin\Exceptions\InvalidVectorOfTrust;
use Spickyyy1\NhsLogin\Exceptions\TokenRequestFailed;
use Spickyyy1\NhsLogin\Exceptions\UserInfoRequestFailed;
use Spickyyy1\NhsLogin\Support\Environment;
use Spickyyy1\NhsLogin\Support\VectorOfTrust;

/**
 * Socialite provider for NHS login.
 *
 * Two things make this more than a normal OAuth provider. NHS login accepts
 * only private_key_jwt client authentication, so there is no client secret to
 * post — every token request carries a signed assertion instead. And the ID
 * token is the actual proof of identity, so it is verified against NHS
 * login's published keys before any user object is built.
 */
class NhsLoginProvider extends AbstractProvider implements ProviderInterface
{
    public const IDENTIFIER = 'NHSLOGIN';

    private const NONCE_SESSION_KEY = 'nhs_login.nonce';

    /** @var string */
    protected $scopeSeparator = ' ';

    /** @var list<string> */
    protected $scopes = ['openid', 'profile'];

    /** @var int */
    protected $encodingType = PHP_QUERY_RFC3986;

    /** @var list<string> */
    protected array $vtr = [];

    protected ?string $nonce = null;

    /**
     * @param  array<string, mixed>  $guzzle
     */
    public function __construct(
        $request,
        $clientId,
        $clientSecret,
        $redirectUrl,
        private readonly Environment $environment,
        private readonly ClientAssertion $assertion,
        private readonly IdTokenVerifier $verifier,
        array $guzzle = [],
    ) {
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl, $guzzle);
    }

    /**
     * Set the Vectors of Trust for this request.
     *
     * Vectors are ORed, components within a vector ANDed. Omitting this
     * entirely makes NHS login default to P9, forcing full identity
     * verification on every user.
     *
     * Each vector is parsed on the way in, so a typo like `P9.Cx` fails here
     * rather than at NHS login, in whichever environment it reached first.
     *
     * @param  list<string|VectorOfTrust>  $vectors
     *
     * @throws InvalidVectorOfTrust
     */
    public function vtr(array $vectors): static
    {
        $this->vtr = array_map(
            static fn (string|VectorOfTrust $vector): string => (string) VectorOfTrust::parse((string) $vector),
            $vectors,
        );

        return $this;
    }

    /**
     * Request the lowest level that still yields an NHS number.
     */
    public function requireVerifiedIdentity(): static
    {
        return $this->vtr(['P5.Cp.Cd', 'P5.Cm']);
    }

    /**
     * Supply the expected nonce yourself.
     *
     * Needed in stateless mode, where there is no session to hold it. The same
     * value must be given to the instance that handles the callback, which is
     * a different instance from the one that redirected.
     */
    public function nonce(string $nonce): static
    {
        $this->nonce = $nonce;

        return $this;
    }

    /**
     * The nonce this request will use, or used.
     *
     * In stateless mode this is the only way to learn what redirect() sent, and
     * the caller has to persist it somewhere the callback can reach — without
     * it the ID token can never be checked against anything.
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function redirect()
    {
        $this->nonce ??= Str::random(40);

        if ($this->usesState()) {
            $this->request->session()->put(self::NONCE_SESSION_KEY, $this->nonce);
        }

        return parent::redirect();
    }

    public function user(): NhsLoginUser
    {
        if ($this->user instanceof NhsLoginUser) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->authorisationCode());

        // Verified before the userinfo call: an unverified ID token means we
        // have no idea who this session belongs to, and asking userinfo would
        // not tell us either.
        $claims = $this->verifier->verify(
            Arr::get($response, 'id_token'),
            $this->environment,
            $this->pullExpectedNonce(),
        );

        $profile = $this->getUserByToken(Arr::get($response, 'access_token'));

        $this->assertSameSubject($claims, $profile);

        $user = $this->mapUserToObject($profile);
        $user->idTokenClaims = $claims;

        $this->user = $user
            ->setToken(Arr::get($response, 'access_token'))
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'))
            ->setApprovedScopes(explode($this->scopeSeparator, (string) Arr::get($response, 'scope', '')));

        return $this->user;
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->environment->authorizeEndpoint(), $state);
    }

    protected function getTokenUrl(): string
    {
        return $this->environment->tokenEndpoint();
    }

    /**
     * @return array<string, mixed>
     */
    protected function getCodeFields($state = null): array
    {
        $fields = parent::getCodeFields($state);

        $fields['nonce'] = $this->nonce ??= Str::random(40);

        if ($this->vtr !== []) {
            $fields['vtr'] = json_encode(array_values($this->vtr), JSON_THROW_ON_ERROR);
        }

        return $fields;
    }

    /**
     * @return array<string, mixed>
     */
    protected function getTokenFields($code): array
    {
        // Deliberately not calling parent: it posts a client_secret, which
        // NHS login does not accept and which we do not have.
        return [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUrl,
            'client_id' => $this->clientId,
            'client_assertion_type' => ClientAssertion::TYPE,
            'client_assertion' => $this->assertion->create($this->environment->tokenEndpoint()),
        ];
    }

    /**
     * Exchange the code, turning a rejection into something diagnosable.
     *
     * Transport failures are left to Guzzle — a refused connection is not NHS
     * login saying no, and pretending otherwise would hide the difference.
     *
     * @return array<string, mixed>
     *
     * @throws TokenRequestFailed
     */
    public function getAccessTokenResponse($code): array
    {
        try {
            $response = $this->getHttpClient()->post($this->getTokenUrl(), [
                RequestOptions::HEADERS => ['Accept' => 'application/json'],
                RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
            ]);
        } catch (BadResponseException $e) {
            throw TokenRequestFailed::fromResponse($e->getResponse(), $e);
        }

        $decoded = json_decode((string) $response->getBody(), true);

        if (! is_array($decoded)) {
            throw TokenRequestFailed::malformed($response);
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * Fetch the profile, given the same treatment as the token exchange.
     *
     * The identity is already established by this point, so a failure here is
     * a profile lookup failing rather than an authentication problem — and it
     * should say so, instead of surfacing as a Guzzle exception the caller was
     * never told to expect.
     *
     * @return array<string, mixed>
     *
     * @throws UserInfoRequestFailed
     */
    protected function getUserByToken($token): array
    {
        try {
            $response = $this->getHttpClient()->get($this->environment->userInfoEndpoint(), [
                'headers' => [
                    'Authorization' => 'Bearer '.$token,
                    'Accept' => 'application/json',
                ],
            ]);
        } catch (BadResponseException $e) {
            throw UserInfoRequestFailed::fromResponse($e->getResponse(), $e);
        }

        $decoded = json_decode((string) $response->getBody(), true);

        if (! is_array($decoded)) {
            throw UserInfoRequestFailed::malformed($response);
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param  array<string, mixed>  $user
     */
    protected function mapUserToObject(array $user): NhsLoginUser
    {
        $name = trim(sprintf(
            '%s %s',
            $user['given_name'] ?? '',
            $user['family_name'] ?? $user['surname'] ?? '',
        ));

        return (new NhsLoginUser)->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'nickname' => null,
            'name' => $name !== '' ? $name : null,
            'email' => $user['email'] ?? null,
            'avatar' => null,
        ]);
    }

    /**
     * Refuse a userinfo response describing someone else.
     *
     * Required by OIDC (Core 5.3.2) and not a formality: the access token and
     * the ID token are separate credentials, and nothing in the token response
     * itself ties them to the same person. Without this, a substituted or
     * misrouted access token yields a verified ID token for one patient and a
     * profile — NHS number included — for another.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $profile
     *
     * @throws InvalidIdToken
     */
    private function assertSameSubject(array $claims, array $profile): void
    {
        $expected = isset($claims['sub']) ? (string) $claims['sub'] : '';
        $actual = isset($profile['sub']) ? (string) $profile['sub'] : '';

        if ($expected === '' || ! hash_equals($expected, $actual)) {
            throw InvalidIdToken::subjectMismatch();
        }
    }

    /**
     * The authorisation code, or an explanation of why there isn't one.
     *
     * A user tapping back at NHS login lands here with error=access_denied and
     * a valid state. Posting the missing code to the token endpoint would turn
     * an ordinary abandoned login into an unreadable HTTP failure.
     *
     * @throws AuthorisationFailed
     */
    protected function authorisationCode(): string
    {
        $error = $this->request->query('error');

        if (is_string($error) && $error !== '') {
            $description = $this->request->query('error_description');

            $this->forgetNonce();

            throw AuthorisationFailed::fromCallback(
                $error,
                is_string($description) ? $description : null,
            );
        }

        $code = $this->getCode();

        if (! is_string($code) || $code === '') {
            $this->forgetNonce();

            throw AuthorisationFailed::missingCode();
        }

        return $code;
    }

    /**
     * @throws InvalidIdToken
     */
    private function pullExpectedNonce(): string
    {
        if (! $this->usesState()) {
            // Stateless: there is no session to have stored it in, so the
            // caller must have supplied it via nonce().
            return $this->nonce ?? throw InvalidIdToken::missingStatelessNonce();
        }

        $nonce = $this->request->session()->pull(self::NONCE_SESSION_KEY);

        return is_string($nonce) && $nonce !== ''
            ? $nonce
            : throw InvalidIdToken::missingNonce();
    }

    /**
     * Abandoned logins should not leave a usable nonce behind in the session.
     */
    private function forgetNonce(): void
    {
        if ($this->usesState()) {
            $this->request->session()->forget(self::NONCE_SESSION_KEY);
        }
    }
}
