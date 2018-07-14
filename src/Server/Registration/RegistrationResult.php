<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Crypto\COSEKey;
use MadWizard\WebAuthn\Server\AttestationResult;

class RegistrationResult
{
    /**
     * @var AttestationResult
     */
    private $attestation;

    public function __construct(AttestationResult $attestation)
    {
        $this->attestation = $attestation;
    }

    /**
     * @return VerificationResult
     */
    public function getVerificationResult(): VerificationResult
    {
        return $this->attestation->getVerificationResult();
    }

    public function getCredentialId() : string
    {
        return $this->attestation->getCredentialId();
    }

    public function getPublicKey() : COSEKey
    {
        return $this->attestation->getPublicKey();
    }
}
