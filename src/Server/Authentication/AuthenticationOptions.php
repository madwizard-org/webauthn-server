<?php


namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Credential\UserCredentialInterface;

class AuthenticationOptions
{
    /**
     * @var UserCredentialInterface[]
     */
    private $allowCredentials = [];

    public function __construct()
    {
    }

    /**
     * @param UserCredentialInterface $credential
     */
    public function addAllowCredential(UserCredentialInterface $credential)
    {
        $this->allowCredentials[] = $credential;
    }

    /**
     * @return UserCredentialInterface[]
     */
    public function getAllowCredentials(): array
    {
        return $this->allowCredentials;
    }
}
