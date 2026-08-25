<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Enums;

/**
 * Scopes advertised by the NHS login discovery document.
 *
 * Requesting a scope you have not been granted at registration causes the
 * authorisation request to fail, so these mirror the published list exactly
 * rather than being a convenience superset.
 */
enum Scope: string
{
    case OpenId = 'openid';
    case Profile = 'profile';
    case ProfileExtended = 'profile_extended';
    case BasicDemographics = 'basic_demographics';
    case Email = 'email';
    case Phone = 'phone';
    case Landline = 'landline';
    case GpIntegrationCredentials = 'gp_integration_credentials';
    case GpRegistrationDetails = 'gp_registration_details';
    case NhsAppCredentials = 'nhs_app_credentials';
    case ClientMetadata = 'client_metadata';

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(static fn (self $scope): string => $scope->value, self::cases());
    }
}
