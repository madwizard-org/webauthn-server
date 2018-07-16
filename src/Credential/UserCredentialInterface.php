<?php


namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Crypto\COSEKey;
use MadWizard\WebAuthn\Format\ByteBuffer;

interface UserCredentialInterface
{
    public function getCredentialId() : string;

    public function getPublicKey() : COSEKey;

    public function getSignatureCounter() : ?int; // todo separate via storage?

    public function getUserHandle() : ByteBuffer;
}
