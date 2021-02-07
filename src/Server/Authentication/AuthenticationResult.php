<?php

namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Credential\UserHandle;

final class AuthenticationResult implements AuthenticationResultInterface
{
    /**
     * @var UserCredentialInterface
     */
    private $userCredential;

    /**
     * @var AuthenticatorData
     */
    private $authenticatorData;

    public function __construct(UserCredentialInterface $userCredential, AuthenticatorData $authenticatorData)
    {
        $this->userCredential = $userCredential;
        $this->authenticatorData = $authenticatorData;
    }

    public function getUserCredential(): UserCredentialInterface
    {
        return $this->userCredential;
    }

    public function getUserHandle(): UserHandle
    {
        return $this->userCredential->getUserHandle();
    }

    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->authenticatorData;
    }

    public function isUserVerified(): bool
    {
        return $this->authenticatorData->isUserVerified();
    }
}
