<?php

namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use const FILTER_VALIDATE_DOMAIN;

class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity
{
    /**
     * @var string|null
     */
    private $id;

    /**
     * PublicKeyCredentialRpEntity constructor.
     *
     * @param string|null $id Relying party ID (valid domain string)
     *
     * @throws WebAuthnException
     */
    public function __construct(string $name, ?string $id = null)
    {
        parent::__construct($name);
        if ($id !== null) {
            $id = filter_var($id, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
            if ($id === false) {
                throw new WebAuthnException('Invalid domain name');
            }
            $this->id = $id;
        }
    }

    public function getId(): ?string
    {
        return $this->id;
    }

    public function getAsArray(): array
    {
        $map = parent::getAsArray();
        if ($this->id !== null) {
            $map['id'] = $this->id;
        }
        return $map;
    }

    public static function fromRelyingParty(RelyingPartyInterface $rp): self     // TODO move?
    {
        $rpEntity = new self($rp->getName(), $rp->getId());
        $rpEntity->setIcon($rp->getIconUrl());
        return $rpEntity;
    }
}
