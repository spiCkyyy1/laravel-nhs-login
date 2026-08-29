<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Testing;

use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Spickyyy1\NhsLogin\Support\VectorOfTrust;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The endpoints NHS login would serve, served locally.
 *
 * Every check the real thing performs is performed here, because a mock that
 * waves requests through would let a broken integration look healthy right up
 * until it met the sandpit.
 */
final class MockIssuerController
{
    public function __construct(
        private readonly MockIssuer $issuer,
        private readonly string $clientId,
        private readonly string $redirectUri,
    ) {}

    public function discovery(): JsonResponse
    {
        return new JsonResponse($this->issuer->discovery());
    }

    public function jwks(): JsonResponse
    {
        try {
            return new JsonResponse($this->issuer->jwks());
        } catch (MockIssuerRejection $e) {
            // Everything else here answers in the OAuth error shape; a key that
            // will not load should not be the one endpoint returning a trace.
            return $e->toResponse();
        }
    }

    public function authorize(Request $request): View|Response
    {
        try {
            // A bad redirect_uri cannot be redirected to — that is the one
            // error that has to be shown here rather than handed to the client.
            $this->assertRedirectUri($request->query('redirect_uri'));
        } catch (MockIssuerRejection $e) {
            return $e->toResponse();
        }

        $clientId = $request->query('client_id');

        if ($clientId !== $this->clientId) {
            // Query parameters can arrive as arrays; interpolating one directly
            // would be a warning rather than an answer.
            return $this->deny($request, 'unauthorized_client', sprintf(
                'Unknown client_id [%s].',
                is_string($clientId) ? $clientId : '(not a string)',
            ));
        }

        if ($request->query('response_type') !== 'code') {
            return $this->deny($request, 'unsupported_response_type', 'Only response_type=code is supported.');
        }

        $scopeParam = $request->query('scope', '');
        $scopes = explode(' ', is_string($scopeParam) ? $scopeParam : '');

        if (! in_array('openid', $scopes, strict: true)) {
            return $this->deny($request, 'invalid_scope', 'The openid scope is required.');
        }

        return view('nhs-login::mock.authorize', [
            'issuer' => $this->issuer->issuer(),
            'vectors' => $this->requestedVectors($request),
            'query' => $request->query(),
            'hasNonce' => $request->query('nonce') !== null,
        ]);
    }

    public function approve(Request $request): Response
    {
        try {
            $this->assertRedirectUri($request->input('redirect_uri'));
        } catch (MockIssuerRejection $e) {
            return $e->toResponse();
        }

        if ($request->input('action') === 'cancel') {
            // What the real thing sends when someone taps back.
            return $this->deny($request, 'access_denied', 'User cancelled the journey.');
        }

        if ($request->input('client_id') !== $this->clientId) {
            return $this->deny($request, 'unauthorized_client', 'Unknown client_id.');
        }

        try {
            $vector = VectorOfTrust::parse((string) $request->input('vector'));
        } catch (Throwable) {
            return $this->deny($request, 'invalid_request', 'The chosen Vector of Trust is not valid.');
        }

        $claims = $this->issuer->claimsFor(
            $vector->level,
            (string) $vector,
            $this->claimOverrides($request),
        );

        $code = $this->issuer->issueCode([
            'claims' => $claims,
            'nonce' => $request->input('nonce'),
            'scope' => (string) $request->input('scope', 'openid profile'),
            'redirect_uri' => $this->redirectUri,
        ]);

        return redirect()->away($this->callbackUrl($request, ['code' => $code]));
    }

    public function token(Request $request): JsonResponse
    {
        try {
            $this->issuer->verifyClientAssertion(
                $request->input('client_assertion'),
                $request->input('client_assertion_type'),
            );

            return new JsonResponse(match ($request->input('grant_type')) {
                'authorization_code' => $this->exchangeAuthorizationCode($request),
                'refresh_token' => $this->exchangeRefreshToken($request),
                default => throw MockIssuerRejection::invalidRequest(
                    'Only grant_type=authorization_code and grant_type=refresh_token are supported.',
                ),
            });
        } catch (MockIssuerRejection $e) {
            return $e->toResponse();
        }
    }

    /**
     * @return array<string, mixed>
     *
     * @throws MockIssuerRejection
     */
    private function exchangeAuthorizationCode(Request $request): array
    {
        $grant = $this->issuer->claimCode((string) $request->input('code', ''));

        if ($grant === null) {
            throw MockIssuerRejection::invalidGrant(
                'Unknown, expired or already-used authorisation code.',
            );
        }

        if ($request->input('redirect_uri') !== $grant['redirect_uri']) {
            throw MockIssuerRejection::invalidGrant(
                'The redirect_uri does not match the one the code was issued for.',
            );
        }

        return $this->issuer->issueTokens($grant['claims'], $grant['nonce'], $grant['scope']);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws MockIssuerRejection
     */
    private function exchangeRefreshToken(Request $request): array
    {
        $refreshToken = (string) $request->input('refresh_token', '');
        $grant = $refreshToken === '' ? null : $this->issuer->redeemRefreshToken($refreshToken);

        if ($grant === null) {
            throw MockIssuerRejection::invalidGrant('Unknown, expired or already-used refresh token.');
        }

        // No nonce: RFC 6749's refresh grant carries none, and the ID token
        // NHS login returns here — like the mock's — is verified without one.
        return $this->issuer->issueTokens($grant['claims'], null, $grant['scope']);
    }

    public function userInfo(Request $request): JsonResponse
    {
        $authorization = $request->header('Authorization');
        $token = Str::after(is_string($authorization) ? $authorization : '', 'Bearer ');
        $claims = $token === '' ? null : $this->issuer->userInfo($token);

        return $claims === null
            ? MockIssuerRejection::invalidGrant('Unknown or expired access token.')->toResponse()
            : new JsonResponse($claims);
    }

    /**
     * Whatever the tester typed into the picker, filtered to claims that exist.
     *
     * @return array<string, string>
     */
    private function claimOverrides(Request $request): array
    {
        $claims = $request->input('claims');

        if (! is_array($claims)) {
            return [];
        }

        return array_filter(
            Arr::only($claims, [
                'sub', 'nhs_number', 'given_name', 'family_name', 'birthdate', 'email', 'phone_number',
            ]),
            static fn (mixed $value): bool => is_string($value) && $value !== '',
        );
    }

    /**
     * The vectors the client asked for, so the picker can default to one that
     * actually satisfies the request.
     *
     * @return list<VectorOfTrust>
     */
    private function requestedVectors(Request $request): array
    {
        $vtr = $request->query('vtr');

        if (! is_string($vtr) || $vtr === '') {
            // NHS login treats an absent vtr as P9.
            return [VectorOfTrust::parse('P9.Cp.Cd')];
        }

        try {
            $decoded = json_decode($vtr, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return [];
        }

        return array_values(array_filter(array_map(
            static function (mixed $vector): ?VectorOfTrust {
                try {
                    return is_string($vector) ? VectorOfTrust::parse($vector) : null;
                } catch (Throwable) {
                    return null;
                }
            },
            is_array($decoded) ? $decoded : [],
        )));
    }

    private function deny(Request $request, string $error, string $description): RedirectResponse
    {
        return redirect()->away($this->callbackUrl($request, [
            'error' => $error,
            'error_description' => $description,
        ]));
    }

    /**
     * @param  array<string, string>  $parameters
     */
    private function callbackUrl(Request $request, array $parameters): string
    {
        $state = $request->input('state');

        if (is_string($state) && $state !== '') {
            $parameters['state'] = $state;
        }

        $separator = str_contains($this->redirectUri, '?') ? '&' : '?';

        return $this->redirectUri.$separator.http_build_query($parameters);
    }

    /**
     * @throws MockIssuerRejection
     */
    private function assertRedirectUri(mixed $redirectUri): void
    {
        if ($redirectUri !== $this->redirectUri) {
            throw MockIssuerRejection::invalidRequest(sprintf(
                'redirect_uri [%s] does not match the one configured for this client [%s]. '
                .'NHS login requires an exact match.',
                is_string($redirectUri) ? $redirectUri : '(missing)',
                $this->redirectUri,
            ));
        }
    }
}
