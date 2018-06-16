<?php


namespace MadWizard\WebAuthn\Crypto;

class DER
{
    public static function length(int $len) : string
    {
        if ($len < 128) {
            return \chr($len);
        }

        while ($len > 0) {
            $lenBytes = \chr($len % 256) . $lenBytes;
            $len = \intdiv($len, 256);
        }

        return \chr(strlen($lenBytes)) . $lenBytes;
    }

    public static function sequence(string $contents) : string
    {
        return "\x30" . self::length(\strlen($contents)) . $contents;
    }

    public static function oid(string $encoded) : string
    {
        return "\x06" . self::length(\strlen($encoded)) . $encoded;
    }

    public static function unsignedInteger(string $bytes) : string
    {
        $len = \strlen($bytes);

        // Remove leading zero bytes
        for ($i = 0; $i < ($len - 1); $i++) {
            if (ord($bytes[$i]) !== 0) {
                break;
            }
        }
        if ($i !== 0) {
            $bytes = \substr($bytes, $i);
        }

        // If most significant bit is set, prefix with another zero to prevent it being seen as negative number
        if (ord($bytes[0]) & 0x80 !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::length(\strlen($bytes)) . $bytes;
    }

    public static function bitString(string $bytes) : string
    {
        $len = \strlen($bytes) + 1;

        return "\x03" . self::length($len) . "\x00" . $bytes;
    }

    public static function nullValue() : string
    {
        return "\x02\x00";
    }
}
