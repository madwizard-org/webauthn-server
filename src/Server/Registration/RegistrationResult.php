<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;

class RegistrationResult
{
    /**
     * @var CredentialId
     */
    private $credentialId;

    /**
     * @var CoseKeyInterface
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

    public function __construct(CredentialId $credentialId, CoseKeyInterface $publicKey, VerificationResult $attestation, int $signCounter)
    {
        $this->credentialId = $credentialId;
        $this->publicKey = $publicKey;
        $this->attestation = $attestation;
        $this->signCounter = $signCounter;
    }

    /**
     * @return CredentialId
     */
    public function getCredentialId(): CredentialId
    {
        return $this->credentialId;
    }

    /**
     * @return CoseKeyInterface
     */
    public function getPublicKey(): CoseKeyInterface
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
