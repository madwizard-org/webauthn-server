<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\AuthenticatorDataInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;

final class RegistrationResult implements RegistrationResultInterface // TODO: use interface everywhere
{ // TODO: add credentialRegistration?

    /**
     * @var CredentialId
     */
    private $credentialId;

    /**
     * @var AuthenticatorDataInterface
     */
    private $authenticatorData;

    /**
     * @var VerificationResult
     */
    private $attestation;

    /**
     * @var MetadataInterface|null
     */
    private $metadata;

    public function __construct(CredentialId $credentialId, AuthenticatorDataInterface $authenticatorData, VerificationResult $attestation, ?MetadataInterface $metadata = null)
    {
        $this->credentialId = $credentialId;
        $this->authenticatorData = $authenticatorData;
        $this->attestation = $attestation;
        $this->metadata = $metadata;
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

    public function getAuthenticatorData(): AuthenticatorDataInterface
    {
        return $this->authenticatorData;
    }

    /**
     * @return VerificationResult
     */
    public function getAttestation(): VerificationResult
    {
        return $this->attestation;
    }

    /**
     * @param VerificationResult $attestation
     */
    public function setAttestation(VerificationResult $attestation): void
    {
        $this->attestation = $attestation;
    }

    /**
     * @return MetadataInterface|null
     */
    public function getMetadata(): ?MetadataInterface
    {
        return $this->metadata;
    }

    public function withMetadata(?MetadataInterface $metadata) : RegistrationResult
    {
        return new RegistrationResult($this->credentialId, $this->authenticatorData, $this->attestation, $metadata);
    }
}
