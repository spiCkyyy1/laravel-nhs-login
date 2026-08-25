<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Psr\Http\Message\RequestInterface;
use Spickyyy1\NhsLogin\ClientAssertion;
use Spickyyy1\NhsLogin\IdTokenVerifier;
use Spickyyy1\NhsLogin\JwksResolver;
use Spickyyy1\NhsLogin\NhsLoginProvider;
use Spickyyy1\NhsLogin\Support\Environment;

/**
 * Builds a provider wired to mocked HTTP so tests never touch NHS login.
 */
final class ProviderFactory
{
    public const CLIENT_ID = 'test-client';

    public const REDIRECT = 'https://app.test/auth/nhs/callback';

    public const ISSUER = 'https://auth.sandpit.signin.nhs.uk';

    public const JWKS_URI = self::ISSUER.'/.well-known/jwks.json';

    private function __construct(
        public readonly NhsLoginProvider $provider,
        public readonly Request $request,
        public readonly RsaKeyPair $keys,
        /** @var \ArrayObject<int, array<string, mixed>> */
        public readonly \ArrayObject $transactions,
        /** @var \ArrayObject<int, bool> */
        private readonly \ArrayObject $jwksFetches,
    ) {}

    /**
     * @param  list<Response>  $responses  queued for the provider's own client
     * @param  list<list<RsaKeyPair>>|null  $jwksSets  key sets served in turn,
     *                                                 the last one repeating
     */
    public static function make(array $responses = [], ?Request $request = null, ?array $jwksSets = null): self
    {
        $keys = RsaKeyPair::shared();
        $environment = Environment::resolve('sandpit', ['sandpit' => self::ISSUER]);

        $transactions = new \ArrayObject;
        $jwksFetches = new \ArrayObject;

        return new self(
            provider: self::provider(
                $responses,
                $environment,
                $keys,
                $request ??= self::request(),
                $transactions,
                $jwksSets ?? [[$keys]],
                $jwksFetches,
            ),
            request: $request,
            keys: $keys,
            transactions: $transactions,
            jwksFetches: $jwksFetches,
        );
    }

    /**
     * How many times the key set was actually fetched over the network.
     */
    public function jwksFetchCount(): int
    {
        return $this->jwksFetches->count();
    }

    public static function request(array $query = []): Request
    {
        $request = Request::create(self::REDIRECT, 'GET', $query);
        $request->setLaravelSession(new Store('nhs-test', new ArraySessionHandler(60)));

        return $request;
    }

    /**
     * @return array<string, mixed>
     */
    public function lastRequestBody(): array
    {
        parse_str((string) $this->lastRequest()->getBody(), $body);

        return $body;
    }

    public function lastRequest(): RequestInterface
    {
        $transactions = $this->transactions->getArrayCopy();

        return end($transactions)['request'];
    }

    public function requestCount(): int
    {
        return $this->transactions->count();
    }

    /**
     * @param  list<Response>  $responses
     */
    private static function provider(
        array $responses,
        Environment $environment,
        RsaKeyPair $keys,
        Request $request,
        \ArrayObject $transactions,
        array $jwksSets,
        \ArrayObject $jwksFetches,
    ): NhsLoginProvider {
        $stack = HandlerStack::create(new MockHandler($responses));
        $stack->push(Middleware::history($transactions));

        $verifier = new IdTokenVerifier(
            jwks: self::jwksResolver($jwksSets, $jwksFetches),
            clientId: self::CLIENT_ID,
        );

        return new NhsLoginProvider(
            request: $request,
            clientId: self::CLIENT_ID,
            clientSecret: '',
            redirectUrl: self::REDIRECT,
            environment: $environment,
            assertion: new ClientAssertion(
                clientId: self::CLIENT_ID,
                privateKey: $keys->privateKey(),
                keyId: $keys->kid,
            ),
            verifier: $verifier,
            guzzle: ['handler' => $stack],
        );
    }

    /**
     * Serves each key set in turn and then repeats the last, so a test can
     * rotate NHS login's keys underneath a running verifier.
     *
     * @param  list<list<RsaKeyPair>>  $jwksSets
     */
    private static function jwksResolver(array $jwksSets, \ArrayObject $fetches): JwksResolver
    {
        $handler = static function () use ($jwksSets, $fetches) {
            $set = $jwksSets[min($fetches->count(), count($jwksSets) - 1)];
            $fetches[] = true;

            return Create::promiseFor(new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode(RsaKeyPair::jwksFor(...$set), JSON_THROW_ON_ERROR),
            ));
        };

        return new JwksResolver(
            new Client(['handler' => HandlerStack::create($handler)]),
            new Repository(new ArrayStore),
        );
    }
}
