<?php


namespace MadWizard\WebAuthn\Policy\Trust;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\UntrustedException;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

interface TrustDecisionManagerInterface
{
    /**
     * Returns if the registration is trusted by this decision manager.
     * Exception UntrustedException is thrown when the registration is not trusted.
     * @throws UntrustedException
     */
    public function verifyTrust(RegistrationResultInterface $registrationResult, ?MetadataInterface $metadata): void;
}
