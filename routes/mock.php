<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Spickyyy1\NhsLogin\Testing\MockIssuerController;

/*
 * The endpoints Environment derives from the issuer, served locally. The paths
 * must match it exactly, or the client will look for them somewhere else.
 */

Route::get('/.well-known/openid-configuration', [MockIssuerController::class, 'discovery'])
    ->name('nhs-login.mock.discovery');

Route::get('/.well-known/jwks.json', [MockIssuerController::class, 'jwks'])
    ->name('nhs-login.mock.jwks');

Route::get('/authorize', [MockIssuerController::class, 'authorize'])
    ->name('nhs-login.mock.authorize');

Route::post('/authorize', [MockIssuerController::class, 'approve'])
    ->name('nhs-login.mock.approve');

Route::post('/token', [MockIssuerController::class, 'token'])
    ->name('nhs-login.mock.token');

Route::get('/userinfo', [MockIssuerController::class, 'userInfo'])
    ->name('nhs-login.mock.userinfo');
