<?php


namespace MadWizard\WebAuthn\Dom;

final class PublicKeyCredentialType
{
    // Currently only one type in the spec
    public const PUBLIC_KEY = 'public-key';

    private function __construct()
    {
    }

    public static function isValidType(string $type) : bool
    {
        return $type === self::PUBLIC_KEY;
    }
}
