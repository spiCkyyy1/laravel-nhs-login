<?php

declare(strict_types=1);

namespace Spickyyy1\NhsLogin\Exceptions;

final class InvalidVectorOfTrust extends NhsLoginException
{
    public static function empty(): self
    {
        return new self('A Vector of Trust cannot be empty.');
    }

    public static function missingLevel(string $vector): self
    {
        return new self("The Vector of Trust [{$vector}] has no identity proofing level (P0, P5 or P9).");
    }

    public static function duplicateLevel(string $vector): self
    {
        return new self("The Vector of Trust [{$vector}] declares more than one identity proofing level.");
    }

    public static function unknownComponent(string $component, string $vector): self
    {
        return new self("Unknown component [{$component}] in the Vector of Trust [{$vector}].");
    }
}
