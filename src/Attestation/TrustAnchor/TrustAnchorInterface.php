<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

interface TrustAnchorInterface
{
    public function getType(): string;
}
