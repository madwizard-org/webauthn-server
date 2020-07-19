<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Format\ByteBuffer;

final class CredentialRegistration
{
    /**
     * @var CredentialId
     */
    private $credentialId;

    /**
     * @var int
     */
    private $signCounter;

    /**
     * @var CoseKeyInterface
     */
    private $publicKey;

    /**
     * @var UserHandle
     */
    private $userHandle;

    /**
     * @var ByteBuffer
     */
    private $attestationObject;

    public function __construct(CredentialId $credentialId, CoseKeyInterface $publicKey, UserHandle $userHandle, ByteBuffer $attestationObject, int $signCounter)
    {
        $this->credentialId = $credentialId;
        $this->publicKey = $publicKey;
        $this->userHandle = $userHandle;
        $this->attestationObject = $attestationObject;
        $this->signCounter = $signCounter;
    }

    /**
     * @return CredentialId
     */
    public function getCredentialId(): CredentialId
    {
        return $this->credentialId;
    }

    /**
     * @return int
     */
    public function getSignCounter(): int
    {
        return $this->signCounter;
    }

    /**
     * @return CoseKeyInterface
     */
    public function getPublicKey(): CoseKeyInterface
    {
        return $this->publicKey;
    }

    /**
     * @return UserHandle
     */
    public function getUserHandle(): UserHandle
    {
        return $this->userHandle;
    }

    /**
     * @return ByteBuffer
     */
    public function getAttestationObject(): ByteBuffer
    {
        return $this->attestationObject;
    }
}
