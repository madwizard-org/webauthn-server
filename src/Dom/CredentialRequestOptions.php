<?php


namespace MadWizard\WebAuthn\Dom;

use Serializable;

class CredentialRequestOptions extends AbstractDictionary implements Serializable
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

    public function serialize()
    {
        return \serialize(['publicKey' => $this->publicKey]);
    }

    public function unserialize($serialized)
    {
        $arr = \unserialize($serialized);
        $this->publicKey = $arr['publicKey'];
    }
}
