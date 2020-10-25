<?php

namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Identifier\AttestationKeyIdentifier;
use MadWizard\WebAuthn\Attestation\Identifier\IdentifierInterface;
use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;
use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Pki\CertificateDetails;

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

    /**
     * @var IdentifierInterface|false|null
     */
    private $cachedIdentifier = false;

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

    public function getIdentifier(): ?IdentifierInterface
    {
        if ($this->cachedIdentifier === false) {
            $this->cachedIdentifier = $this->determineIdentifier();
        }
        return $this->cachedIdentifier;
    }

    public function withMetadata(?MetadataInterface $metadata): RegistrationResult
    {
        return new RegistrationResult($this->credentialId, $this->authenticatorData, $this->attestationObject, $this->verificationResult, $metadata);
    }

    private static function pkIdFromPemCertificate(string $pem): IdentifierInterface
    {
        $cert = CertificateDetails::fromPem($pem);
        return new AttestationKeyIdentifier($cert->getPublicKeyIdentifier());
    }

    private function determineIdentifier(): ?IdentifierInterface
    {
        // If a valid AAGUID is present, this is the main identifier. Do not look for others.
        $identifier = $this->authenticatorData->getAaguid();
        if ($identifier !== null && !$identifier->isZeroAaguid()) {
            return $identifier;
        }

        // Use public key identifier for U2F only. Apple for example generates a certificate
        // for each credential using the credential's key so using the public key identifier
        // would 'leak' a personal public key to the MDS.
        if ($this->attestationObject->getFormat() === FidoU2fAttestationStatement::FORMAT_ID) {
            // If certificates are available, get the attestation certificate's public key identifier
            $trustPath = $this->verificationResult->getTrustPath();
            if ($trustPath instanceof CertificateTrustPath) {
                $certs = $trustPath->getCertificates();
                if (isset($certs[0])) {
                    return self::pkIdFromPemCertificate($certs[0]->asPem());
                }
            }
        }
        return null;
    }
}
