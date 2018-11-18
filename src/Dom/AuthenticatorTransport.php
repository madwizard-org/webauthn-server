<?php


namespace MadWizard\WebAuthn\Dom;

final class AuthenticatorTransport
{
    /**
     * USB
     */
    public const USB = 'usb';

    /**
     * Near Field Communication (NFC).
     */
    public const NFC = 'nfc';

    /**
     * Bluetooth Smart (Bluetooth Low Energy / BLE).
     */
    public const BLE = 'ble';

    /**
     * Client device-specific transport. These authenticators are not removable from the client device.
     */
    public const INTERNAL = 'internal';

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    public static function isValidValue($value) : bool
    {
        return in_array($value, self::allKnownTransports(), true);
    }

    public static function allKnownTransports() : array
    {
        return [self::USB, self::NFC, self::BLE, self::INTERNAL];
    }
}
