<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Format\ByteBuffer;

class CredentialRegistration
{
    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var CoseKeyInterface
     */
    private $publicKey;

    /**
     * @var ByteBuffer
     */
    private $userHandle;

    public function __construct(string $credentialId, CoseKeyInterface $publicKey, ByteBuffer $userHandle)
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
     * @return CoseKeyInterface
     */
    public function getPublicKey(): CoseKeyInterface
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
