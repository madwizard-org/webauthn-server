<?php


namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialRpEntity;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialUserEntity;
use MadWizard\WebAuthn\Format\ByteBuffer;

trait DomTestTrait
{
    private function createUserEntity() : PublicKeyCredentialUserEntity
    {
        return new PublicKeyCredentialUserEntity('testuser', ByteBuffer::fromHex('1234'), 'Test user');
    }

    private function createRpEntity() : PublicKeyCredentialRpEntity
    {
        return new PublicKeyCredentialRpEntity('RP');
    }

    private function createChallenge() : ByteBuffer
    {
        return ByteBuffer::fromHex('0123456789abcdef');
    }
}
