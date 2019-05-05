<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;

class SelfTrustAnchor implements TrustAnchorInterface
{
    public function isTrusted(VerificationResult $verificationResult): TrustStatus
    {
        return $verificationResult->getAttestationType() === AttestationType::SELF ? TrustStatus::trusted() : TrustStatus::notTrusted();
    }
}
