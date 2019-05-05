<?php


namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustAnchorSetInterface;

interface WebAuthnPolicyInterface
{
    public function getAttestationFormatRegistry() : AttestationFormatRegistryInterface;

    public function getTrustAnchorSet() : TrustAnchorSetInterface;
}
