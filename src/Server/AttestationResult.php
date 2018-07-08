<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Crypto\COSEKey;

class AttestationResult  // TODO: merge registration and attestation result?
{
    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var COSEKey
     */
    private $publicKey;

    /**
     * @var VerificationResult
     */
    private $attestation;

    public function __construct(string $credentialId, COSEKey $publicKey, VerificationResult $attestation)
    {
        $this->credentialId = $credentialId;
        $this->publicKey = $publicKey;
        $this->attestation = $attestation;
    }

    /**
     * @return string
     */
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    /**
     * @return COSEKey
     */
    public function getPublicKey(): COSEKey
    {
        return $this->publicKey;
    }

    /**
     * @return VerificationResult
     */
    public function getAttestation(): VerificationResult
    {
        return $this->attestation;
    }
}
