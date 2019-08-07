<?php


namespace MadWizard\WebAuthn\Tests\Credential;



use InvalidArgumentException;
use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding as b64;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class UserHandleTest extends TestCase
{

    private function checkId(UserHandle $id)
    {
        $this->assertSame('3c4fbf08', bin2hex($id->toBinary()));
        $this->assertSame('3c4fbf08', $id->toHex());
        $this->assertSame('PE-_CA', $id->toString());
        $this->assertTrue(ByteBuffer::fromHex('3c4fbf08')->equals($id->toBuffer()));
    }

    public function testString()
    {
        $id = UserHandle::fromString('PE-_CA');
        $this->checkId($id);
    }

    public function testHex()
    {
        $id = UserHandle::fromHex('3c4fbf08');
        $this->checkId($id);
    }

    public function testInvalidHex()
    {
        $this->expectException(InvalidArgumentException::class);//TODO webauth exception?
        UserHandle::fromHex('sg');
    }

    public function testBuffer()
    {
        $id = UserHandle::fromBuffer(ByteBuffer::fromHex('3c4fbf08'));
        $this->checkId($id);
    }

    public function testBinary()
    {
        $id = UserHandle::fromBinary("\x3c\x4f\xbf\x08");
        $this->checkId($id);
    }

    public function testLength()
    {
        $this->expectException(WebAuthnException::class);
        UserHandle::fromBinary(str_pad('x', UserHandle::MAX_USER_HANDLE_BYTES + 1));
    }

    public function testEquals()
    {
        $id1 = UserHandle::fromHex('3c4fbf08');
        $id2 = UserHandle::fromHex('3c4fbf08');
        $id3 = UserHandle::fromHex('3c4fbf09');
        $this->assertTrue($id1->equals($id1));
        $this->assertTrue($id1->equals($id2));
        $this->assertFalse($id2->equals($id3));
    }
}