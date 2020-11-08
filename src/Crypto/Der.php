<?php

namespace MadWizard\WebAuthn\Crypto;

class Der
{
    private static function length(int $len): string
    {
        if ($len < 128) {
            return \chr($len);
        }

        $lenBytes = '';
        while ($len > 0) {
            $lenBytes = \chr($len % 256) . $lenBytes;
            $len = \intdiv($len, 256);
        }
        return \chr(0x80 | \strlen($lenBytes)) . $lenBytes;
    }

    public static function sequence(string $contents): string
    {
        return "\x30" . self::length(\strlen($contents)) . $contents;
    }

    public static function oid(string $encoded): string
    {
        return "\x06" . self::length(\strlen($encoded)) . $encoded;
    }

    public static function unsignedInteger(string $bytes): string
    {
        $len = \strlen($bytes);

        // Remove leading zero bytes
        for ($i = 0; $i < ($len - 1); $i++) {
            if (\ord($bytes[$i]) !== 0) {
                break;
            }
        }
        if ($i !== 0) {
            $bytes = \substr($bytes, $i);
        }

        // If most significant bit is set, prefix with another zero to prevent it being seen as negative number
        if ((\ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::length(\strlen($bytes)) . $bytes;
    }

    public static function bitString(string $bytes): string
    {
        $len = \strlen($bytes) + 1;

        return "\x03" . self::length($len) . "\x00" . $bytes;
    }

    public static function octetString(string $bytes): string
    {
        $len = \strlen($bytes);

        return "\x04" . self::length($len) . $bytes;
    }

    public static function contextTag(int $tag, bool $constructed, string $content): string
    {
        return \chr(($tag & 0x1F) |   // Context specific tag number
            (1 << 7) |  // Context-specific flag
            ($constructed ? (1 << 5) : 0)) .
            self::length(\strlen($content)) .
            $content;
    }

    public static function nullValue(): string
    {
        return "\x05\x00";
    }

    public static function pem(string $type, string $der): string
    {
        return sprintf("-----BEGIN %s-----\n", strtoupper($type)) .
            chunk_split(base64_encode($der), 64, "\n") .
            sprintf("-----END %s-----\n", strtoupper($type));
    }
}
