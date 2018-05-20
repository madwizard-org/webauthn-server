<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Format\ByteBuffer;

class AuthenticatorAttestationResponse extends AbstractAuthenticatorResponse implements AuthenticatorAttestationResponseInterface
{
    /**
     * @var ByteBuffer
     */
    private $attestationObject;

    public function __construct(string $clientDataJSON, ByteBuffer $attestationObject)
    {
        parent::__construct($clientDataJSON);
        $this->attestationObject = $attestationObject;
    }

    public function getAttestationObject() : ByteBuffer
    {
        return $this->attestationObject;
    }
}
