<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\CoseKey;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;

class UserCredential implements UserCredentialInterface
{
    /**
     * @var CredentialId
     */
    private $credentialId;

    /**
     * @var CoseKeyInterface
     */
    private $publicKey;

    /**
     * @var UserHandle
     */
    private $userHandle;

    public function __construct(CredentialId $credentialId, CoseKeyInterface $publicKey, UserHandle $userHandle)
    {
        $this->credentialId = $credentialId;
        $this->publicKey = $publicKey;
        $this->userHandle = $userHandle;
    }

    /**
     * @return CredentialId
     */
    public function getCredentialId(): CredentialId
    {
        return $this->credentialId;
    }

    /**
     * @return CoseKey
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
}
