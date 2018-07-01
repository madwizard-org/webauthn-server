<?php


namespace MadWizard\WebAuthn\Dom;

class CredentialRequestOptions extends AbstractDictionary
{
    /**
     * @var PublicKeyCredentialRequestOptions|null
     */
    private $publicKey;

    public function __construct()
    {
    }

    public function setPublicKeyOptions(PublicKeyCredentialRequestOptions $options)
    {
        $this->publicKey = $options;
    }

    public function getAsArray(): array
    {
        $map = [];
        if ($this->publicKey !== null) {
            $map['publicKey'] = $this->publicKey;
        }
        return $map;
    }
}
