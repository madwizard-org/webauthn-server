<?php


namespace MadWizard\WebAuthn\Policy\Trust;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

interface TrustDecisionManagerInterface
{
    public function isTrusted(RegistrationResultInterface $registrationResult, ?MetadataInterface $metadata): bool;
}
