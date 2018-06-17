<?php


namespace MadWizard\WebAuthn\Tests\Crypto;

use MadWizard\WebAuthn\Crypto\DER;
use PHPUnit\Framework\TestCase;
use function bin2hex;
use function hex2bin;
use function str_repeat;

class DERTest extends TestCase
{
    public function testSequence()
    {
        $der = DER::sequence(hex2bin('123456'));
        $this->assertSame('3003123456', bin2hex($der));

        $long = str_repeat(hex2bin('0500'), 300);
        $der = DER::sequence($long);
        $this->assertSame('30820258' . bin2hex($long), bin2hex($der));
    }

    public function testOid()
    {
        $der = DER::oid(hex2bin('2a8648ce3d0201'));
        $this->assertSame('06072a8648ce3d0201', bin2hex($der));
    }

    public function testUnsignedInteger()
    {
        $der = DER::unsignedInteger(hex2bin('00'));
        $this->assertSame('020100', bin2hex($der));

        $der = DER::unsignedInteger(hex2bin('00000000'));
        $this->assertSame('020100', bin2hex($der));

        $der = DER::unsignedInteger(hex2bin('123456'));
        $this->assertSame('0203123456', bin2hex($der));

        $der = DER::unsignedInteger(hex2bin('00000000123456'));
        $this->assertSame('0203123456', bin2hex($der));

        $der = DER::unsignedInteger(hex2bin('87654321'));
        $this->assertSame('02050087654321', bin2hex($der));

        $der = DER::unsignedInteger(hex2bin('00000087654321'));
        $this->assertSame('02050087654321', bin2hex($der));
    }

    public function testBitString()
    {
        $der = DER::bitString(hex2bin('123456'));

        $this->assertSame('030400123456', bin2hex($der));
    }

    public function testNullValue()
    {
        $der = DER::nullValue();
        $this->assertSame('0500', bin2hex($der));
    }
}
