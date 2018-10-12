<?php


namespace MadWizard\WebAuthn\Tests\Crypto;

use MadWizard\WebAuthn\Crypto\Der;
use PHPUnit\Framework\TestCase;
use function bin2hex;
use function hex2bin;
use function str_repeat;

class DerTest extends TestCase
{
    public function testSequence()
    {
        $der = Der::sequence(hex2bin('123456'));
        $this->assertSame('3003123456', bin2hex($der));

        $long = str_repeat(hex2bin('0500'), 300);
        $der = Der::sequence($long);
        $this->assertSame('30820258' . bin2hex($long), bin2hex($der));
    }

    public function testOid()
    {
        $der = Der::oid(hex2bin('2a8648ce3d0201'));
        $this->assertSame('06072a8648ce3d0201', bin2hex($der));
    }

    public function testUnsignedInteger()
    {
        $der = Der::unsignedInteger(hex2bin('00'));
        $this->assertSame('020100', bin2hex($der));

        $der = Der::unsignedInteger(hex2bin('00000000'));
        $this->assertSame('020100', bin2hex($der));

        $der = Der::unsignedInteger(hex2bin('123456'));
        $this->assertSame('0203123456', bin2hex($der));

        $der = Der::unsignedInteger(hex2bin('00000000123456'));
        $this->assertSame('0203123456', bin2hex($der));

        $der = Der::unsignedInteger(hex2bin('87654321'));
        $this->assertSame('02050087654321', bin2hex($der));

        $der = Der::unsignedInteger(hex2bin('00000087654321'));
        $this->assertSame('02050087654321', bin2hex($der));
    }

    public function testBitString()
    {
        $der = Der::bitString(hex2bin('123456'));

        $this->assertSame('030400123456', bin2hex($der));
    }

    public function testNullValue()
    {
        $der = Der::nullValue();
        $this->assertSame('0500', bin2hex($der));
    }
}
