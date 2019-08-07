<?php


namespace MadWizard\WebAuthn\Attestation\Identifier;

interface IdentifierInterface
{
    /**
     * @return string
     */
    public function getType(): string;

    /**
     * @return string
     */
    public function toString(): string;

    public function equals(IdentifierInterface $identifier) : bool;
}
