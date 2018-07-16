<?php


namespace MadWizard\WebAuthn\Dom;

class TokenBindingStatus
{
    /**
     * Token binding was used when communicating with the Relying Party.
     */
    public const PRESENT = 'present';

    /**
     * The client supports token binding, but it was not negotiated when communicating with the Relying Party.
     */
    public const SUPPORTED = 'supported';

    /**
     * The client does not support token binding.
     */
    public const NOT_SUPPORTED = 'not-supported';

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    public static function isValidValue(string $value) : bool
    {
        return ($value === self::PRESENT || $value === self::SUPPORTED || $value === self::NOT_SUPPORTED);
    }
}
