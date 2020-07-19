<?php

namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Credential\UserCredentialInterface;

class AuthenticationResult
{
    /**
     * @var UserCredentialInterface
     */
    private $userCredential;

    public function __construct(UserCredentialInterface $userCredential)
    {
        $this->userCredential = $userCredential;
    }

    public function getUserCredential(): UserCredentialInterface
    {
        return $this->userCredential;
    }
}
