<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Spickyyy1\NhsLogin\Enums\IdentityProofingLevel;
use Spickyyy1\NhsLogin\Events\NhsLoginAuthenticated;
use Spickyyy1\NhsLogin\Events\NhsLoginAuthenticationFailed;
use Spickyyy1\NhsLogin\Exceptions\AuthorisationFailed;

/**
 * The audit trail a clinical service is expected to keep (DCB0129, DSPT)
 * should not depend on every application remembering to build one — see the
 * docblocks on both events for what a listener may safely log.
 */
beforeEach(function () {
    $this->app['request']->setLaravelSession($this->app['session']->driver());
});

it('dispatches NhsLoginAuthenticated with the subject and identity level, not the claims', function () {
    Event::fake([NhsLoginAuthenticated::class]);

    $user = signIn();

    Event::assertDispatched(
        NhsLoginAuthenticated::class,
        fn (NhsLoginAuthenticated $event): bool => $event->subject === $user->getId()
            && $event->identityProofingLevel === IdentityProofingLevel::P9
            && $event->user === $user,
    );
});

it('dispatches NhsLoginAuthenticationFailed when the user cancels', function () {
    Event::fake([NhsLoginAuthenticationFailed::class]);

    expect(fn () => signIn(['action' => 'cancel']))->toThrow(AuthorisationFailed::class);

    Event::assertDispatched(
        NhsLoginAuthenticationFailed::class,
        fn (NhsLoginAuthenticationFailed $event): bool => $event->exception instanceof AuthorisationFailed
            && $event->exception->wasCancelled(),
    );
});
