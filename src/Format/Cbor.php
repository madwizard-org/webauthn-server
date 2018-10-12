<?php


namespace MadWizard\WebAuthn\Format;

final class Cbor
{
    public const MAJOR_UNSIGNED_INT = 0;

    public const MAJOR_TEXT_STRING = 3;

    public const MAJOR_FLOAT_SIMPLE = 7;

    public const MAJOR_NEGATIVE_INT = 1;

    public const MAJOR_ARRAY = 4;

    public const MAJOR_TAG = 6;

    public const MAJOR_MAP = 5;

    public const MAJOR_BYTE_STRING = 2;

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }
}
