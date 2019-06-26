<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;

interface TrustAnchorSetInterface
{
    public function isTrusted(VerificationResult $verificationResult): TrustStatus;
}
