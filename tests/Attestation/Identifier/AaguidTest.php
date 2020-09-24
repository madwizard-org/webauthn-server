<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Identifier;

use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class AaguidTest extends TestCase
{
    public function testTooShort()
    {
        $this->expectException(ParseException::class);
        new Aaguid(new ByteBuffer('a'));
    }

    public function testTooLong()
    {
        $this->expectException(ParseException::class);
        new Aaguid(ByteBuffer::fromHex('00112233445566778899aabbccddeeff11'));
    }

    public function testConstructRaw()
    {
        $hex = '00112233445566778899aabbccddeeff';
        $aaguid = new Aaguid(ByteBuffer::fromHex($hex));
        self::assertSame($hex, $aaguid->getHex());
    }

    public function testToString()
    {
        $aaguid = new Aaguid(ByteBuffer::fromHex('00112233445566778899aabbccddeeff'));
        self::assertSame('00112233-4455-6677-8899-aabbccddeeff', $aaguid->toString());
    }

    public function testParseString()
    {
        $str = '00112233-4455-6677-8899-aabbccddeeff';
        $aaguid = Aaguid::parseString($str);
        self::assertSame($str, $aaguid->toString());
    }

    public function testInvalidString()
    {
        $str = '001122334455-6677-8899-aabbccddeeff';
        $this->expectException(ParseException::class);
        Aaguid::parseString($str);
    }

    public function testZero()
    {
        self::assertFalse(Aaguid::parseString('00112233-4455-6677-8899-aabbccddeeff')->isZeroAaguid());
        self::assertTrue(Aaguid::parseString('00000000-0000-0000-0000-000000000000')->isZeroAaguid());
        self::assertFalse(Aaguid::parseString('00000000-0000-0000-0000-000000000001')->isZeroAaguid());
        self::assertFalse(Aaguid::parseString('10000000-0000-0000-0000-000000000000')->isZeroAaguid());
    }

    public function testEqual()
    {
        $a = Aaguid::parseString('00112233-4455-6677-8899-aabbccddeeff');
        $a2 = Aaguid::parseString('00112233-4455-6677-8899-aabbccddeeff');
        $b = Aaguid::parseString('90112233-4455-6677-8899-aabbccddeeff');
        $c = Aaguid::parseString('00112233-4455-6677-8899-aabbccddeef9');
        self::assertTrue($a->equals($a));
        self::assertTrue($a->equals($a2));
        self::assertFalse($a->equals($b));
        self::assertFalse($a->equals($c));
    }
}
