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

    public function getCredentialId(): CredentialId
    {
        return $this->credentialId;
    }

    public function getPublicKey(): CoseKeyInterface
    {
        return $this->authenticatorData->getKey();
    }

    public function getVerificationResult(): VerificationResult
    {
        return $this->attestation;
    }

    public function getSignatureCounter(): int
    {
        return $this->authenticatorData->getSignCount();
    }

    public function getAuthenticatorData(): AuthenticatorDataInterface
    {
        return $this->authenticatorData;
    }

    public function getAttestation(): VerificationResult
    {
        return $this->attestation;
    }

    public function setAttestation(VerificationResult $attestation): void
    {
        $this->attestation = $attestation;
    }

    public function getMetadata(): ?MetadataInterface
    {
        return $this->metadata;
    }

    public function withMetadata(?MetadataInterface $metadata): RegistrationResult
    {
        return new RegistrationResult($this->credentialId, $this->authenticatorData, $this->attestation, $metadata);
    }
}
