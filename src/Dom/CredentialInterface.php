<?php


namespace MadWizard\WebAuthn\Dom;

interface CredentialInterface
{
    /**
     * The credential's identifier. The requirements for the identifier are distinct for each type of credential.
     * @return string
     */
    public function getId(): string;

    /**
     * Specifies the kind of credential represented by this object.
     * @return string
     */
    public function getType(): string;
}
