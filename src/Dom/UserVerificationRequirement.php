<?php

namespace MadWizard\WebAuthn\Dom;

final class UserVerificationRequirement
{
    /**
     * This value indicates that the Relying Party requires user verification for the operation and will fail
     * the operation if the response does not have the UV flag set.
     */
    public const REQUIRED = 'required';

    /**
     * This value indicates that the Relying Party prefers user verification for the operation if possible,
     * but will not fail the operation if the response does not have the UV flag set.
     */
    public const PREFERRED = 'preferred';

    /**
     * This value indicates that the Relying Party does not want user verification employed during the operation
     * (e.g., in the interest of minimizing disruption to the user interaction flow).
     */
    public const DISCOURAGED = 'discouraged';

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    public static function isValidValue(string $value): bool
    {
        return $value === self::REQUIRED || $value === self::PREFERRED || $value === self::DISCOURAGED;
    }
}
