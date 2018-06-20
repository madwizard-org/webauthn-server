<?php


namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\AuthenticatorTransport;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialDescriptor;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialType;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class PublicKeyCredentialDescriptorTest extends TestCase
{
    public function testDescriptor()
    {
        $credId = ByteBuffer::fromHex('11223344556677');
        $key = new PublicKeyCredentialDescriptor($credId, PublicKeyCredentialType::PUBLIC_KEY);

        $this->assertTrue($key->getId()->equals($credId));
        $this->assertSame(PublicKeyCredentialType::PUBLIC_KEY, $key->getType());
        $key->addTransport(AuthenticatorTransport::USB);
        $key->addTransport(AuthenticatorTransport::NFC);

        $this->assertSame(
            [AuthenticatorTransport::USB, AuthenticatorTransport::NFC],
            $key->getTransports()
        );

        $data = $key->getJsonData();

        $this->assertSame(
            [
                'type' => 'public-key',
                'id' => 'ESIzRFVmdw',
                'transports' => ['usb', 'nfc']
            ],
            $data
        );
    }

    public function testWrongType()
    {
        $this->expectException(WebAuthnException::class);

        new PublicKeyCredentialDescriptor(ByteBuffer::fromHex('11223344556677'), 'wrongtype');
    }
}
