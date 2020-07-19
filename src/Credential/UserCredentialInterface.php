<?php

namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\CoseKeyInterface;

interface UserCredentialInterface
{
    public function getCredentialId(): CredentialId;

    public function getPublicKey(): CoseKeyInterface;

    public function getUserHandle(): UserHandle;
}
