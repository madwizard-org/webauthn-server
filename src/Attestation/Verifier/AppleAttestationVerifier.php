<?php

namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInAttestationFormat;
use MadWizard\WebAuthn\Attestation\Statement\AppleAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Crypto\Der;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Pki\CertificateDetails;

final class AppleAttestationVerifier implements AttestationVerifierInterface
{
    private const OID_APPLE_CERTIFICATE_POLICY = '1.2.840.113635.100.8.2';

    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash): VerificationResult
    {
        if (!($attStmt instanceof AppleAttestationStatement)) {
            throw new VerificationException('Expecting AppleAttestationStatement');
        }

        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // -> this is done in AppleAttestationStatement

        // 2. Concatenate authenticatorData and clientDataHash to form nonceToHash.
        $nonceToHash = $authenticatorData->getRaw()->getBinaryString() . $clientDataHash;

        // 3. Perform SHA-256 hash of nonceToHash to produce nonce.
        $nonce = hash('sha256', $nonceToHash, true);

        $x5c = $attStmt->getCertificates();

        $credCert = $x5c[0] ?? null;
        if ($credCert === null) {
            throw new VerificationException('No certificates in attestation.');
        }

        // 4. Verify that nonce equals the value of the extension with OID ( 1.2.840.113635.100.8.2 ) in credCert.
        $cert = CertificateDetails::fromPem($credCert->asPem());
        $extension = $cert->getExtensionData(self::OID_APPLE_CERTIFICATE_POLICY);
        if ($extension === null) {
            throw new VerificationException('Missing apple extension in attestation certificate.');
        }

        $correctExtensionValue = Der::sequence(Der::contextTag(1, true, Der::octetString($nonce)));

        if (!hash_equals($correctExtensionValue, $extension->getValue()->getBinaryString())) {
            throw new VerificationException("The nonce in the certificate's extension does not match the calculated nonce.");
        }

        // 5. Verify credential public key matches the Subject Public Key of credCert.
        $certPublicKeyDer = $cert->getPublicKeyDer();
        $authenticatorPublicKeyDer = $authenticatorData->getKey()->asDer();

        if ($certPublicKeyDer !== $authenticatorPublicKeyDer) {
            throw new VerificationException('The public key of the attestation certificate is different from the public key in the authenticator data.');
        }

        // 6. If successful, return implementation-specific values representing attestation type Anonymization CA and attestation trust path x5c.
        return new VerificationResult(AttestationType::ANON_CA, new CertificateTrustPath(...$x5c));
    }

    public function getSupportedFormat(): AttestationFormatInterface
    {
        return new BuiltInAttestationFormat(
            AppleAttestationStatement::FORMAT_ID,
            AppleAttestationStatement::class,
            $this
        );
    }
}
