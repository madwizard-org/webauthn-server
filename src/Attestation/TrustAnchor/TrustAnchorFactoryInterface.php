<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

interface TrustAnchorFactoryInterface
{
    public function createTrustAnchor(string $name) : TrustAnchorInterface;
}
