<?php


namespace MadWizard\WebAuthn\Tests\Credential;

use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class CredentialIdTest extends TestCase
{
    private function checkId(CredentialId $id)
    {
        $this->assertSame('3c4fbf08', bin2hex($id->toBinary()));
        $this->assertSame('3c4fbf08', $id->toHex());
        $this->assertSame('PE-_CA', $id->toString());
        $this->assertTrue(ByteBuffer::fromHex('3c4fbf08')->equals($id->toBuffer()));
    }

    public function testString()
    {
        $id = CredentialId::fromString('PE-_CA');
        $this->checkId($id);
    }

    public function testHex()
    {
        $id = CredentialId::fromHex('3c4fbf08');
        $this->checkId($id);
    }

    public function testBuffer()
    {
        $id = CredentialId::fromBuffer(ByteBuffer::fromHex('3c4fbf08'));
        $this->checkId($id);
    }

    public function testBinary()
    {
        $id = CredentialId::fromBinary("\x3c\x4f\xbf\x08");
        $this->checkId($id);
    }

    public function testEquals()
    {
        $id1 = CredentialId::fromHex('3c4fbf08');
        $id2 = CredentialId::fromHex('3c4fbf08');
        $id3 = CredentialId::fromHex('3c4fbf09');
        $this->assertTrue($id1->equals($id1));
        $this->assertTrue($id1->equals($id2));
        $this->assertFalse($id2->equals($id3));
    }
}
