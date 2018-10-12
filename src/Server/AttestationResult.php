<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Crypto\CoseKey;

class AttestationResult  // TODO: merge registration and attestation result?
{
    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var CoseKey
     */
    private $publicKey;

    /**
     * @var VerificationResult
     */
    private $attestation;

    public function __construct(string $credentialId, CoseKey $publicKey, VerificationResult $attestation)
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
     * @return CoseKey
     */
    public function getPublicKey(): CoseKey
    {
        return $this->publicKey;
    }

    /**
     * @return VerificationResult
     */
    public function getVerificationResult(): VerificationResult
    {
        return $this->attestation;
    }
}
