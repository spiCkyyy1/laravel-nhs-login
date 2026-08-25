<?php

declare(strict_types=1);

/**
 * The default configuration must not serve a token issuer.
 */
it('does not mount the mock issuer unless it is switched on', function () {
    $this->get('/nhs-login-mock/authorize')->assertNotFound();
    $this->get('/nhs-login-mock/.well-known/jwks.json')->assertNotFound();
    $this->post('/nhs-login-mock/token')->assertNotFound();
});
