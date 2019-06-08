<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Crypto\CoseKey;

class RegistrationResult
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

    /**
     * @var int
     */
    private $signCounter;

    public function __construct(string $credentialId, CoseKey $publicKey, VerificationResult $attestation, int $signCounter)
    {
        $this->credentialId = $credentialId;
        $this->publicKey = $publicKey;
        $this->attestation = $attestation;
        $this->signCounter = $signCounter;
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

    /**
     * @return int
     */
    public function getSignatureCounter(): int
    {
        return $this->signCounter;
    }
}
