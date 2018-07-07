<?php


namespace MadWizard\WebAuthn\Format;

use MadWizard\WebAuthn\Exception\CBORException;

class CBOREncoder
{
    public static function encodeInteger(int $i): string
    {
        if ($i < 0) {
            $i = -($i + 1);
            $major = CBOR::MAJOR_NEGATIVE_INT;
        } else {
            $major = CBOR::MAJOR_UNSIGNED_INT;
        }

        $bytes = self::integerBytes($i, $minorVal);

        return chr(($major << 5) | $minorVal) . $bytes;
    }

    public static function encodeTextString(string $text): string
    {
        $lengthBytes = self::integerBytes(\strlen($text), $minorVal);
        return chr((CBOR::MAJOR_TEXT_STRING << 5) | $minorVal) . $lengthBytes . $text;
    }

    public static function encodeByteString(ByteBuffer $bytes): string
    {
        $lengthBytes = self::integerBytes($bytes->getLength(), $minorVal);
        return chr((CBOR::MAJOR_BYTE_STRING << 5) | $minorVal) . $lengthBytes . $bytes->getBinaryString();
    }

    public static function encodeMapValues(array $map): string
    {
        // Use canonical sorting. Shorter keys (as CBOR bytes) always go before longer keys. When length is the same
        // a byte for byte comparison is done.
        uksort($map, function (string $key1, string $key2) {
            $cmp = \strlen($key1) <=> \strlen($key2);
            return ($cmp === 0) ? ($key1 <=> $key2) : $cmp;
        });

        $mapContent = '';
        foreach ($map as $k => $v) {
            $mapContent .= $k . $v;
        }
        $lengthBytes = self::integerBytes(count($map), $minorVal);
        return chr((CBOR::MAJOR_MAP << 5) | $minorVal) . $lengthBytes . $mapContent;
    }

    public static function encodeMap(array $map): string
    {
        $mapValues = [];

        foreach ($map as $k => $v) {
            $mapValues[self::encodeSingleValue($k)] = self::encodeSingleValue($v);
        }

        return self::encodeMapValues($mapValues);
    }

    private static function integerBytes(int $i, &$minorVal): string
    {
        if ($i < 24) {
            $minorVal = $i;
            return '';
        }

        if ($i < 2 ** 8) {
            $minorVal = 24;
            return pack('C', $i);
        }

        if ($i < 2 ** 16) {
            $minorVal = 25;
            return pack('n', $i);
        }

        if (PHP_INT_SIZE < 8 || $i < 2 ** 32) {
            $minorVal = 26;
            return pack('N', $i);
        }

        $minorVal = 27;
        return pack('J', $i);
    }

    public static function encodeSingleValue($k): string
    {
        if (\is_int($k)) {
            return self::encodeInteger($k);
        }
        if (\is_string($k)) {
            return self::encodeTextString($k);
        }
        if ($k instanceof ByteBuffer) {
            return self::encodeByteString($k);
        }
        throw new CBORException('Unsupported type for encodeSingleValue');
    }
}
