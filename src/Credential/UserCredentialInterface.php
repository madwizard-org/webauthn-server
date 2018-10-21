<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\CoseKey;
use MadWizard\WebAuthn\Format\ByteBuffer;

interface UserCredentialInterface
{
    public function getCredentialId() : string;

    public function getPublicKey() : CoseKey;

    public function getUserHandle() : ByteBuffer;
}
