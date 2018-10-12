<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\CoseKey;
use MadWizard\WebAuthn\Format\ByteBuffer;

class CredentialRegistration
{
    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var CoseKey
     */
    private $publicKey;

    /**
     * @var ByteBuffer
     */
    private $userHandle;

    public function __construct(string $credentialId, CoseKey $publicKey, ByteBuffer $userHandle)
    {
        $this->credentialId = $credentialId;
        $this->publicKey = $publicKey;
        $this->userHandle = $userHandle;
    }

    /**
     * @return string
     */
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    /**
     * @return CoseKey
     */
    public function getPublicKey(): CoseKey
    {
        return $this->publicKey;
    }

    /**
     * @return ByteBuffer
     */
    public function getUserHandle(): ByteBuffer
    {
        return $this->userHandle;
    }
}
