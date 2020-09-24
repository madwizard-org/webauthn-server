<?php

namespace MadWizard\WebAuthn\Tests\Credential;

use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Credential\CredentialRegistration;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class CredentialRegistrationTest extends TestCase
{
    public function testCredentialRegistration()
    {
        $id = CredentialId::fromHex('123456');
        /**
         * @var CoseKeyInterface $key
         */
        $key = $this->createMock(CoseKeyInterface::class);
        $handle = UserHandle::fromString('aabbcc');
        $attObj = ByteBuffer::fromHex('123456');
        $credential = new CredentialRegistration($id, $key, $handle, $attObj, 123);
        self::assertSame($id, $credential->getCredentialId());
        self::assertSame($key, $credential->getPublicKey());
        self::assertSame($handle, $credential->getUserHandle());
        self::assertSame($attObj, $credential->getAttestationObject());
        self::assertSame(123, $credential->getSignCounter());
    }
}
