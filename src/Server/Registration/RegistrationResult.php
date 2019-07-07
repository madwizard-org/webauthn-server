<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
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
     * @var AuthenticatorData
     */
    private $authenticatorData;

    /**
     * @var VerificationResult
     */
    private $attestation;

    public function __construct(CredentialId $credentialId, AuthenticatorData $authenticatorData, VerificationResult $attestation)
    {
        $this->credentialId = $credentialId;
        $this->authenticatorData = $authenticatorData;
        $this->attestation = $attestation;
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
        return $this->authenticatorData->getKey();
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
        return $this->authenticatorData->getSignCount();
    }

    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->authenticatorData;
    }
}
