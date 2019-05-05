<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;

class NoneTrustAnchor implements TrustAnchorInterface
{
    public function isTrusted(VerificationResult $verificationResult): TrustStatus
    {
        if ($verificationResult->getAttestationType() !== AttestationType::BASIC) {
            return TrustStatus::notTrusted();
        }
    }
}
