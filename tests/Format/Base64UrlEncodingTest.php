<?php

namespace MadWizard\WebAuthn\Tests\Format;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding as b64;
use PHPUnit\Framework\TestCase;
use function bin2hex;
use function hex2bin;

class Base64UrlEncodingTest extends TestCase
{
    public function testEncode()
    {
        self::assertSame('', b64::encode(''));
        self::assertSame('YQ', b64::encode('a'));
        self::assertSame('YWI', b64::encode('ab'));
        self::assertSame('YWJj', b64::encode('abc'));
        self::assertSame('YWJjZA', b64::encode('abcd'));
        self::assertSame('YWJjZGVmZ2hpag', b64::encode('abcdefghij'));
        self::assertSame('PE-_CA', b64::encode(hex2bin('3c4fbf08')));
    }

    public function testDecode()
    {
        self::assertSame('', b64::decode(''));
        self::assertSame('a', b64::decode('YQ'));
        self::assertSame('ab', b64::decode('YWI'));
        self::assertSame('abc', b64::decode('YWJj'));
        self::assertSame('abcd', b64::decode('YWJjZA'));
        self::assertSame('abcdefghij', b64::decode('YWJjZGVmZ2hpag'));
        self::assertSame('3c4fbf08', bin2hex(b64::decode('PE-_CA')));
    }

    public function testInvalid()
    {
        $this->expectException(ParseException::class);
        b64::decode('ab#c');
    }
}
