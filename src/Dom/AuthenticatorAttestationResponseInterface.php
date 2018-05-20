<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface AuthenticatorAttestationResponseInterface extends AuthenticatorResponseInterface
{
    public function getAttestationObject() : ByteBuffer;
}
