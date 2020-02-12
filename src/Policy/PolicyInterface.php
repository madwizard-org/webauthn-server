<?php


namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Metadata\MetadataResolverInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManagerInterface;

interface PolicyInterface
{
    public function getAttestationFormatRegistry() : AttestationFormatRegistryInterface;

    // TODO refactor? - prevent class becoming a service locator

    public function getTrustDecisionManager() : TrustDecisionManagerInterface;

    public function getMetadataResolver() : MetadataResolverInterface;

    public function getRelyingParty() : RelyingPartyInterface;
}
