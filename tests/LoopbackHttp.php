<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Tests;

use Closure;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * A Guzzle client whose requests are answered by the test application itself.
 *
 * The package's server-to-server calls — token, userinfo, JWKS — leave through
 * Guzzle, so a test using the mounted mock issuer would otherwise have to open
 * a real socket to itself. This dispatches them straight into the HTTP kernel
 * instead, which is what makes a complete login testable in process.
 */
final class LoopbackHttp
{
    /**
     * @param  Closure(string, string, array<string, mixed>, array<string, string>): SymfonyResponse  $dispatch
     */
    public static function client(Closure $dispatch): Client
    {
        return new Client(['handler' => HandlerStack::create(self::handler($dispatch))]);
    }

    /**
     * @param  Closure(string, string, array<string, mixed>, array<string, string>): SymfonyResponse  $dispatch
     */
    private static function handler(Closure $dispatch): callable
    {
        return static function (RequestInterface $request) use ($dispatch) {
            $parameters = [];

            if ($request->getMethod() === 'POST') {
                parse_str((string) $request->getBody(), $parameters);
            }

            $response = $dispatch(
                $request->getMethod(),
                (string) $request->getUri(),
                $parameters,
                self::serverVars($request),
            );

            return Create::promiseFor(new GuzzleResponse(
                $response->getStatusCode(),
                $response->headers->all(),
                (string) $response->getContent(),
            ));
        };
    }

    /**
     * @return array<string, string>
     */
    private static function serverVars(RequestInterface $request): array
    {
        $server = [];

        foreach ($request->getHeaders() as $name => $values) {
            $key = 'HTTP_'.str_replace('-', '_', strtoupper($name));
            $server[$key] = implode(', ', $values);
        }

        if ($request->hasHeader('Content-Type')) {
            $server['CONTENT_TYPE'] = $request->getHeaderLine('Content-Type');
        }

        return $server;
    }
}
