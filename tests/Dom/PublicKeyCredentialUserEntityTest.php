<?php


namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialUserEntity;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;
use function str_repeat;

class PublicKeyCredentialUserEntityTest extends TestCase
{
    public function testSimple()
    {
        $user = new PublicKeyCredentialUserEntity('eddy', ByteBuffer::fromHex('aabb4455'), 'Eddy Wally');
        $this->assertSame('eddy', $user->getName());
        $this->assertSame('Eddy Wally', $user->getDisplayName());
        $this->assertSame('aabb4455', $user->getId()->getHex());
    }

    public function testEmptyID()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageRegExp('~empty~i');
        new PublicKeyCredentialUserEntity('eddy', new ByteBuffer(''), 'Eddy Wally');
    }

    public function testTooLargeID()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageRegExp('~cannot be larger~i');
        new PublicKeyCredentialUserEntity('eddy', new ByteBuffer(str_repeat('x', 65)), 'Eddy Wally');
    }
}
