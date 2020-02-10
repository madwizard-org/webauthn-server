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
        $this->assertSame($hex, $aaguid->getHex());
    }

    public function testToString()
    {
        $aaguid = new Aaguid(ByteBuffer::fromHex('00112233445566778899aabbccddeeff'));
        $this->assertSame('00112233-4455-6677-8899-aabbccddeeff', $aaguid->toString());
    }

    public function testParseString()
    {
        $str = '00112233-4455-6677-8899-aabbccddeeff';
        $aaguid = Aaguid::parseString($str);
        $this->assertSame($str, $aaguid->toString());
    }

    public function testInvalidString()
    {
        $str = '001122334455-6677-8899-aabbccddeeff';
        $this->expectException(ParseException::class);
        Aaguid::parseString($str);
    }

    public function testZero()
    {
        $this->assertFalse(Aaguid::parseString('00112233-4455-6677-8899-aabbccddeeff')->isZeroAaguid());
        $this->assertTrue(Aaguid::parseString('00000000-0000-0000-0000-000000000000')->isZeroAaguid());
        $this->assertFalse(Aaguid::parseString('00000000-0000-0000-0000-000000000001')->isZeroAaguid());
        $this->assertFalse(Aaguid::parseString('10000000-0000-0000-0000-000000000000')->isZeroAaguid());
    }

    public function testEqual()
    {
        $a = Aaguid::parseString('00112233-4455-6677-8899-aabbccddeeff');
        $a2 = Aaguid::parseString('00112233-4455-6677-8899-aabbccddeeff');
        $b = Aaguid::parseString('90112233-4455-6677-8899-aabbccddeeff');
        $c = Aaguid::parseString('00112233-4455-6677-8899-aabbccddeef9');
        $this->assertTrue($a->equals($a));
        $this->assertTrue($a->equals($a2));
        $this->assertFalse($a->equals($b));
        $this->assertFalse($a->equals($c));
    }
}
