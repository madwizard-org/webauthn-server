<?php


namespace MadWizard\WebAuthn\Dom;

final class AuthenticatorAttachment
{
    /**
     * Platform attachment
     * The respective authenticator is attached using platform-specific transports.
     * Usually, authenticators of this class are non-removable from the platform. A public key credential bound
     * to a platform authenticator is called a platform credential.
     */
    public const PLATFORM = 'platform';

    /**
     * Cross-platform attachment
     * The respective authenticator is attached using cross-platform transports. Authenticators of this class are
     * removable from, and can "roam" among, client platforms. A public key credential bound to a roaming authenticator
     * is called a roaming credential.
     */
    public const CROSS_PLATFORM = 'cross-platform';

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    public static function isValidValue($value) : bool
    {
        return ($value === self::PLATFORM || $value === self::CROSS_PLATFORM);
    }
}
