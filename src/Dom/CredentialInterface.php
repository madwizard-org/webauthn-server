<?php

namespace MadWizard\WebAuthn\Dom;

interface CredentialInterface
{
    /**
     * The credential's identifier. The requirements for the identifier are distinct for each type of credential.
     */
    public function getId(): string;

    /**
     * Specifies the kind of credential represented by this object.
     */
    public function getType(): string;
}
