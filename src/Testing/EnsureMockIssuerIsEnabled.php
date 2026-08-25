<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Testing;

use Closure;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Re-checks, on every request, that the mock issuer is allowed to answer.
 *
 * The guards in the service provider run at boot, and boot-time guards do not
 * survive route caching: `route:cache` boots the application, serialises
 * whatever routes exist at that moment, and production then loads the compiled
 * file without booting anything. Cache the routes once with the mock enabled —
 * which is exactly the state a developer's machine is in — and the endpoints
 * ship.
 *
 * This runs inside the request, reads the configuration as it is now, and
 * answers 404 rather than 403: an endpoint that should not exist should not
 * advertise that it exists.
 */
final class EnsureMockIssuerIsEnabled
{
    public function __construct(private readonly Application $app) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->allowed()) {
            abort(404);
        }

        return $next($request);
    }

    private function allowed(): bool
    {
        /** @var bool $enabled */
        $enabled = $this->app->make('config')->get('nhs-login.mock.enabled', false);

        return $enabled && $this->app->environment(['local', 'testing']);
    }
}
