<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\COSEKey;
use MadWizard\WebAuthn\Format\ByteBuffer;

class CredentialRegistration
{
    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var COSEKey
     */
    private $publicKey;

    /**
     * @var ByteBuffer
     */
    private $userHandle;

    public function __construct(string $credentialId, COSEKey $publicKey, ByteBuffer $userHandle)
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
     * @return COSEKey
     */
    public function getPublicKey(): COSEKey
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
