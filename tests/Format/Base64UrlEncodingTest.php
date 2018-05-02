<?php


namespace MadWizard\WebAuthn\Tests\Format;

use MadWizard\WebAuthn\Format\Base64UrlEncoding as b64;
use PHPUnit\Framework\TestCase;
use function bin2hex;
use function hex2bin;

class Base64UrlEncodingTest extends TestCase
{
    public function testEncode()
    {
        $this->assertSame('', b64::encode(''));
        $this->assertSame('YQ', b64::encode('a'));
        $this->assertSame('YWI', b64::encode('ab'));
        $this->assertSame('YWJj', b64::encode('abc'));
        $this->assertSame('YWJjZA', b64::encode('abcd'));
        $this->assertSame('YWJjZGVmZ2hpag', b64::encode('abcdefghij'));
        $this->assertSame('PE-_CA', b64::encode(hex2bin('3c4fbf08')));
    }

    public function testDecode()
    {
        $this->assertSame('', b64::decode(''));
        $this->assertSame('a', b64::decode('YQ'));
        $this->assertSame('ab', b64::decode('YWI'));
        $this->assertSame('abc', b64::decode('YWJj'));
        $this->assertSame('abcd', b64::decode('YWJjZA'));
        $this->assertSame('abcdefghij', b64::decode('YWJjZGVmZ2hpag'));
        $this->assertSame('3c4fbf08', bin2hex(b64::decode('PE-_CA')));
    }

    // TODO: different exception

    /**
     * @expectedException \MadWizard\WebAuthn\Exception\WebAuthnException
     */
    public function testInvalid()
    {
        b64::decode('ab#c');
    }
}
