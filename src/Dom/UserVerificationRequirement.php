<?php


namespace MadWizard\WebAuthn\Dom;

final class UserVerificationRequirement
{
    public const REQUIRED = 'required';

    public const PREFERRED = 'preferred';

    public const DISCOURAGED = 'discouraged';

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    public static function isValidValue(string $value) : bool
    {
        return ($value === self::REQUIRED || $value === self::PREFERRED || $value === self::DISCOURAGED);
    }
}
