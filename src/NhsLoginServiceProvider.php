<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin;

use GuzzleHttp\Client;
use Illuminate\Container\Container as ConcreteContainer;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\CachesRoutes;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;
use Laravel\Socialite\SocialiteManager;
use Spickyyy1\NhsLogin\Exceptions\NhsLoginConfigurationException;
use Spickyyy1\NhsLogin\Support\Environment;
use Spickyyy1\NhsLogin\Support\PrivateKey;
use Spickyyy1\NhsLogin\Testing\EnsureMockIssuerIsEnabled;
use Spickyyy1\NhsLogin\Testing\MockIssuer;
use Spickyyy1\NhsLogin\Testing\MockIssuerController;

final class NhsLoginServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/nhs-login.php', 'nhs-login');

        $this->app->singleton(Environment::class, static function (Container $app): Environment {
            $config = $app['config']->get('nhs-login');

            return Environment::resolve(
                (string) $config['environment'],
                $config['issuers'],
                $config['issuer'] ?? null,
            );
        });

        $this->app->singleton(JwksResolver::class, static function (Container $app): JwksResolver {
            $config = $app['config']->get('nhs-login');

            return new JwksResolver(
                new Client(['timeout' => (int) $config['timeout']]),
                $app['cache']->store($config['jwks_cache_store']),
                (int) $config['jwks_ttl'],
                (int) ($config['jwks_refresh_cooldown'] ?? 60),
            );
        });

        $this->app->singleton(ClientAssertion::class, static function (Container $app): ClientAssertion {
            $config = $app['config']->get('nhs-login');

            return new ClientAssertion(
                clientId: self::clientId($config),
                privateKey: PrivateKey::resolve($config['private_key'], $config['private_key_path']),
                passphrase: $config['private_key_passphrase'],
                keyId: $config['key_id'],
                ttl: (int) $config['assertion_ttl'],
            );
        });

        $this->registerMockIssuer();

        $this->app->singleton(IdTokenVerifier::class, static function (Container $app): IdTokenVerifier {
            $config = $app['config']->get('nhs-login');

            return new IdTokenVerifier(
                jwks: $app->make(JwksResolver::class),
                clientId: self::clientId($config),
                leeway: (int) $config['leeway'],
            );
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/nhs-login.php' => config_path('nhs-login.php'),
            ], 'nhs-login-config');
        }

        $this->registerSocialiteDriver();
        $this->registerMockRoutes();
    }

    /**
     * Bind the mock issuer. Nothing is resolved unless its routes are hit.
     */
    private function registerMockIssuer(): void
    {
        $this->app->singleton(MockIssuer::class, static function (Container $app): MockIssuer {
            $config = $app['config']->get('nhs-login');

            return new MockIssuer(
                cache: $app['cache']->store($config['jwks_cache_store']),
                environment: $app->make(Environment::class),
                clientId: self::clientId($config),
                clientPublicKey: PrivateKey::publicKey(
                    PrivateKey::resolve($config['private_key'], $config['private_key_path']),
                    $config['private_key_passphrase'],
                ),
            );
        });

        $this->app->singleton(MockIssuerController::class, static function (Container $app): MockIssuerController {
            $config = $app['config']->get('nhs-login');

            return new MockIssuerController(
                issuer: $app->make(MockIssuer::class),
                clientId: self::clientId($config),
                redirectUri: (string) $config['redirect'],
            );
        });
    }

    /**
     * Mount the mock issuer, refusing anywhere it could do harm.
     *
     * It signs ID tokens that this application will accept, for any NHS number
     * typed into a form. That is fine on a laptop and catastrophic anywhere
     * else, so the guards fail loudly rather than quietly skipping.
     *
     * @throws NhsLoginConfigurationException
     */
    private function registerMockRoutes(): void
    {
        $config = $this->app['config']->get('nhs-login.mock');

        if (! ($config['enabled'] ?? false)) {
            return;
        }

        if (! $this->app->environment(['local', 'testing'])) {
            throw NhsLoginConfigurationException::mockEnabledOutsideDevelopment(
                (string) $this->app->environment(),
            );
        }

        $this->loadViewsFrom(__DIR__.'/../resources/views', 'nhs-login');

        // Not $config['prefix'] directly: mergeConfigFrom is a shallow merge,
        // so a published config whose mock block omits this key would leave it
        // undefined — and an empty prefix mounts the issuer at the site root,
        // where it shadows the application's own routes.
        $prefix = (string) ($config['prefix'] ?? 'nhs-login-mock');

        if (trim($prefix, '/') === '') {
            throw NhsLoginConfigurationException::emptyMockPrefix();
        }
        $issuer = $this->app->make(Environment::class)->issuer;

        // Deliberately not an equality check against url(): that depends on the
        // host the current request came in on, so reaching the same site by
        // 127.0.0.1 instead of localhost would break the boot. What actually
        // matters is that this is not pointed at NHS login, where the mock
        // would sit there unreachable while real logins failed.
        $real = array_map(
            static fn (string $candidate): string => rtrim($candidate, '/'),
            $this->app['config']->get('nhs-login.issuers', []),
        );

        if (in_array($issuer, $real, strict: true)) {
            throw NhsLoginConfigurationException::mockIssuerNotLocal(
                $issuer,
                rtrim((string) $this->app['config']->get('app.url'), '/').'/'.$prefix,
            );
        }

        if ($this->app instanceof CachesRoutes && $this->app->routesAreCached()) {
            // Already compiled in. Registering them again would only duplicate
            // them; the middleware below is what keeps the cached copies safe.
            return;
        }

        Route::prefix($prefix)
            // The gate is a middleware, not this boot-time branch, because a
            // compiled route file outlives the configuration that produced it.
            ->middleware([EnsureMockIssuerIsEnabled::class, ...($config['middleware'] ?? [])])
            ->group(__DIR__.'/../routes/mock.php');
    }

    /**
     * Hook the driver onto Socialite without forcing it to resolve.
     *
     * Resolving the factory during boot would build Socialite on every
     * request, including the ones that never touch authentication.
     */
    private function registerSocialiteDriver(): void
    {
        // Manager::extend() rebinds the callback's $this to the manager, so
        // the callback it receives must not reach for anything on this class.
        // The factory is captured here, while $this still means what it says.
        $factory = fn (): NhsLoginProvider => $this->createProvider();

        $extend = static function (SocialiteManager $socialite) use ($factory): void {
            $socialite->extend('nhslogin', function () use ($factory): NhsLoginProvider {
                return $factory();
            });
        };

        if ($this->app->resolved(Factory::class)) {
            /** @var SocialiteManager $socialite */
            $socialite = $this->app->make(Factory::class);

            $extend($socialite);

            return;
        }

        $this->app->afterResolving(Factory::class, $extend);
    }

    /**
     * Built by hand rather than via Socialite's buildProvider(), which only
     * knows how to pass id, secret and redirect — this provider also needs the
     * environment, the assertion signer and the token verifier.
     */
    private function createProvider(): NhsLoginProvider
    {
        $config = $this->app['config']->get('nhs-login');

        $provider = new NhsLoginProvider(
            request: $this->app->make('request'),
            clientId: self::clientId($config),
            clientSecret: '',
            redirectUrl: (string) $config['redirect'],
            environment: $this->app->make(Environment::class),
            assertion: $this->app->make(ClientAssertion::class),
            verifier: $this->app->make(IdTokenVerifier::class),
            guzzle: ['timeout' => (int) $config['timeout']],
        );

        $this->keepRequestCurrent($provider);

        return $provider->setScopes($config['scopes'])->vtr($config['vtr']);
    }

    /**
     * Hand the provider each new request as it arrives.
     *
     * Socialite's Manager caches driver instances and the manager itself is a
     * container singleton, so on a long-lived worker — Octane, Swoole, RoadRunner
     * — the provider built during one request is the one used for the next, still
     * holding the first request's session and query string. The failure is not
     * that logins break: hasInvalidState() would compare a stale state against a
     * stale parameter and could *pass* while the real callback went unread.
     *
     * Rebinding is how the framework itself keeps Redirector and AuthManager
     * current, and on a traditional worker where 'request' is bound once it
     * costs nothing.
     */
    private function keepRequestCurrent(NhsLoginProvider $provider): void
    {
        $container = $this->app;

        // rebinding() lives on the concrete container rather than the contract.
        // Every real application has it; skipping is only for the container a
        // test might substitute, where there is nothing to keep current anyway.
        if (! $container instanceof ConcreteContainer) {
            return;
        }

        $container->rebinding('request', static function ($app, Request $request) use ($provider): void {
            $provider->setRequest($request);
        });
    }

    /**
     * @param  array<string, mixed>  $config
     *
     * @throws NhsLoginConfigurationException
     */
    private static function clientId(array $config): string
    {
        $clientId = $config['client_id'] ?? null;

        return is_string($clientId) && $clientId !== ''
            ? $clientId
            : throw NhsLoginConfigurationException::missingClientId();
    }
}
