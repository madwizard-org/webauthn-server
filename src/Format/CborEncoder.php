<?php

namespace MadWizard\WebAuthn\Format;

use MadWizard\WebAuthn\Exception\CborException;

final class CborEncoder
{
    public static function encodeInteger(int $i): string
    {
        if ($i < 0) {
            $i = -($i + 1);
            $major = Cbor::MAJOR_NEGATIVE_INT;
        } else {
            $major = Cbor::MAJOR_UNSIGNED_INT;
        }

        $bytes = self::integerBytes($i, $minorVal);

        return chr(($major << 5) | $minorVal) . $bytes;
    }

    public static function encodeTextString(string $text): string
    {
        $lengthBytes = self::integerBytes(\strlen($text), $minorVal);
        return chr((Cbor::MAJOR_TEXT_STRING << 5) | $minorVal) . $lengthBytes . $text;
    }

    public static function encodeByteString(ByteBuffer $bytes): string
    {
        $lengthBytes = self::integerBytes($bytes->getLength(), $minorVal);
        return chr((Cbor::MAJOR_BYTE_STRING << 5) | $minorVal) . $lengthBytes . $bytes->getBinaryString();
    }

    private static function sortAndEncodeMapEntries(array $map): string
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
        return chr((Cbor::MAJOR_MAP << 5) | $minorVal) . $lengthBytes . $mapContent;
    }

    public static function encodeMap(CborMap $map): string
    {
        $mapValues = [];

        foreach ($map->getEntries() as $entry) {
            $mapValues[self::encodeSingleValue($entry[0])] = self::encodeSingleValue($entry[1]);
        }

        return self::sortAndEncodeMapEntries($mapValues);
    }

    private static function integerBytes(int $i, ?int &$minorVal): string
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

    /**
     * @param int|string|ByteBuffer|CborMap|bool|null $value
     *
     * @throws CborException
     */
    public static function encodeSingleValue($value): string
    {
        if (\is_int($value)) {
            return self::encodeInteger($value);
        }
        if (\is_string($value)) {
            return self::encodeTextString($value);
        }
        if ($value instanceof ByteBuffer) {
            return self::encodeByteString($value);
        }
        if ($value instanceof CborMap) {
            return self::encodeMap($value);
        }
        if ($value === false) {
            return chr(0xF4);
        }
        if ($value === true) {
            return chr(0xF5);
        }
        if ($value === null) {
            return chr(0xF6);
        }
        // @phpstan-ignore-next-line
        throw new CborException(sprintf('Unsupported type "%s" for encodeSingleValue', gettype($value)));
    }
}
