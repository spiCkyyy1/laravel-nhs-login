<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Exceptions;

final class NhsLoginConfigurationException extends NhsLoginException
{
    /**
     * @param  list<string>  $known
     */
    public static function unknownEnvironment(string $name, array $known): self
    {
        return new self(sprintf(
            'Unknown NHS login environment [%s]. Set NHS_LOGIN_ENVIRONMENT to one of: %s.',
            $name,
            implode(', ', $known),
        ));
    }

    public static function missingPrivateKey(): self
    {
        return new self(
            'No NHS login private key configured. Set NHS_LOGIN_PRIVATE_KEY to the PEM contents '
            .'or NHS_LOGIN_PRIVATE_KEY_PATH to a readable file.',
        );
    }

    public static function unreadablePrivateKey(string $path): self
    {
        return new self("The NHS login private key at [{$path}] could not be read.");
    }

    public static function unusablePrivateKey(): self
    {
        return new self(
            'The NHS login private key could not be loaded. It must be an RSA key in PEM format, '
            .'and the passphrase must be correct if it is encrypted.',
        );
    }

    public static function mockEnabledOutsideDevelopment(string $environment): self
    {
        return new self(sprintf(
            'The NHS login mock issuer is enabled but the application environment is [%s]. '
            .'It mints valid ID tokens for any NHS number, so it will not start outside local '
            .'or testing. Unset NHS_LOGIN_MOCK.',
            $environment,
        ));
    }

    public static function mockIssuerNotLocal(string $issuer, string $expected): self
    {
        return new self(sprintf(
            'The NHS login mock issuer is enabled, but this application is configured to talk to '
            .'[%s]. Set NHS_LOGIN_ISSUER="%s" so it reaches the mock instead.',
            $issuer,
            $expected,
        ));
    }

    public static function emptyMockPrefix(): self
    {
        return new self(
            'The NHS login mock issuer has an empty route prefix, which would mount it at the '
            .'application root and shadow your own routes. Set nhs-login.mock.prefix.',
        );
    }

    public static function missingClientId(): self
    {
        return new self('No NHS login client ID configured. Set NHS_LOGIN_CLIENT_ID.');
    }
}
