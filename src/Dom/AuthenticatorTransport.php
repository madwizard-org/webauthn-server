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
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    public static function allKnownTransports() : array
    {
        return [self::USB, self::NFC, self::BLE];
    }
}
