<?php

namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Credential\UserHandle;

interface AuthenticationResultInterface
{
    public function getUserCredential(): UserCredentialInterface;

    public function getUserHandle(): UserHandle;
}
