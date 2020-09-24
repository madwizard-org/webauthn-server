<?php

namespace MadWizard\WebAuthn\Tests\Credential;

use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Credential\UserCredential;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use PHPUnit\Framework\TestCase;

class UserCredentialTest extends TestCase
{
    public function testUserCredential()
    {
        $id = CredentialId::fromHex('123456');
        /**
         * @var CoseKeyInterface $key
         */
        $key = $this->createMock(CoseKeyInterface::class);
        $handle = UserHandle::fromString('aabbcc');
        $credential = new UserCredential($id, $key, $handle);
        self::assertSame($id, $credential->getCredentialId());
        self::assertSame($key, $credential->getPublicKey());
        self::assertSame($handle, $credential->getUserHandle());
    }
}
