<?php


namespace MadWizard\WebAuthn\Tests\Helper;

use MadWizard\WebAuthn\Format\ByteBuffer;
use function hex2bin;
use function preg_replace;

class HexData
{
    public static function bin(string $hexStr) : string
    {
        $hexStr = preg_replace('~#.+~m', '', $hexStr);
        $hexStr = preg_replace('~\s+~', '', $hexStr);
        return hex2bin($hexStr);
    }

    public static function buf(string $hexStr) : ByteBuffer
    {
        return new ByteBuffer(self::bin($hexStr));
    }
}
