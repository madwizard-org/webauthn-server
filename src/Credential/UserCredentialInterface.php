<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Format\ByteBuffer;

interface UserCredentialInterface
{
    public function getCredentialId() : string;

    public function getPublicKey() : CoseKeyInterface;

    public function getUserHandle() : ByteBuffer;
}
