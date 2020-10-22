<?php

namespace MadWizard\WebAuthn\Dom;

final class ResidentKeyRequirement
{
    public const DISCOURAGED = 'discouraged';

    // Not in us yet until level 2 spec
    // public const PREFERRED = 'preferred';

    public const REQUIRED = 'required';

    public const DEFAULT = self::DISCOURAGED;

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    public static function isValidValue(string $value): bool
    {
        return $value === self::DISCOURAGED || $value === self::REQUIRED;
    }
}
