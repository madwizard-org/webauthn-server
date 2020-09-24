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
        self::assertSame('eddy', $user->getName());
        self::assertSame('Eddy Wally', $user->getDisplayName());
        self::assertSame('aabb4455', $user->getId()->getHex());
    }

    public function testEmptyID()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~empty~i');
        new PublicKeyCredentialUserEntity('eddy', new ByteBuffer(''), 'Eddy Wally');
    }

    public function testTooLargeID()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~cannot be larger~i');
        new PublicKeyCredentialUserEntity('eddy', new ByteBuffer(str_repeat('x', 65)), 'Eddy Wally');
    }
}
