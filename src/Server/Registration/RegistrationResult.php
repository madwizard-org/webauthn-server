<?php

namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
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
     * @var AuthenticatorData
     */
    private $authenticatorData;

    /**
     * @var VerificationResult
     */
    private $verificationResult;

    /**
     * @var MetadataInterface|null
     */
    private $metadata;

    /**
     * @var AttestationObject
     */
    private $attestationObject;

    public function __construct(CredentialId $credentialId, AuthenticatorData $authenticatorData, AttestationObject $attestationObject, VerificationResult $verificationResult, ?MetadataInterface $metadata = null)
    {
        $this->credentialId = $credentialId;
        $this->authenticatorData = $authenticatorData;
        $this->verificationResult = $verificationResult;
        $this->metadata = $metadata;
        $this->attestationObject = $attestationObject;
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
        return $this->verificationResult;
    }

    public function getSignatureCounter(): int
    {
        return $this->authenticatorData->getSignCount();
    }

    public function getAttestationObject(): AttestationObject
    {
        return $this->attestationObject;
    }

    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->authenticatorData;
    }

    public function getMetadata(): ?MetadataInterface
    {
        return $this->metadata;
    }

    public function withMetadata(?MetadataInterface $metadata): RegistrationResult
    {
        return new RegistrationResult($this->credentialId, $this->authenticatorData, $this->attestationObject, $this->verificationResult, $metadata);
    }
}
