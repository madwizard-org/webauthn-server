<?php


namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;

interface WebAuthnPolicyInterface
{
    public function getAttestationFormatRegistry() : AttestationFormatRegistryInterface;
}
