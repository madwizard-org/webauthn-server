<?php

namespace MadWizard\WebAuthn\Tests\Helper;

use MadWizard\WebAuthn\Format\ByteBuffer;
use function hex2bin;
use function preg_replace;

class HexData
{
    public static function bin(string $hexStr): string
    {
        return hex2bin(self::hex($hexStr));
    }

    public static function buf(string $hexStr): ByteBuffer
    {
        return new ByteBuffer(self::bin($hexStr));
    }

    public static function hex(string $hexStr): string
    {
        $hexStr = preg_replace('~#.+~m', '', $hexStr);
        return preg_replace('~\s+~', '', $hexStr);
    }
}
