<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\COSEKey;

interface UserCredentialInterface
{
    public function getCredentialId() : string;

    public function getPublicKey() : COSEKey;

    public function getSignatureCounter() : ?int;
}
