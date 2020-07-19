<?php

namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Fido\FidoAaguidExtension;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\TpmAttestationStatement;
use MadWizard\WebAuthn\Attestation\Tpm\TpmEccParameters;
use MadWizard\WebAuthn\Attestation\Tpm\TpmPublic;
use MadWizard\WebAuthn\Attestation\Tpm\TpmRsaParameters;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Crypto\CoseHash;
use MadWizard\WebAuthn\Crypto\Ec2Key;
use MadWizard\WebAuthn\Crypto\RsaKey;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Pki\CertificateDetails;
use MadWizard\WebAuthn\Pki\CertificateDetailsInterface;
use MadWizard\WebAuthn\Pki\CertificateParser;
use MadWizard\WebAuthn\Pki\CertificateParserInterface;

final class TpmAttestationVerifier implements AttestationVerifierInterface
{
    /**
     * @var CertificateParserInterface
     */
    private $certificateParser;

    public const OID_TCG_AT_TPM_MANUFACTURER = '2.23.133.2.1';

    public const OID_TCG_AT_TPM_MODEL = '2.23.133.2.2';

    public const OID_TCG_AT_TPM_VERSION = '2.23.133.2.3';

    public const OID_TCG_KP_AIK_CERTIFICATE = '2.23.133.8.3';

    public function __construct(?CertificateParserInterface $certificateParser = null)
    {
        if ($certificateParser === null) {
            $certificateParser = new CertificateParser();
        }
        $this->certificateParser = $certificateParser;
    }

    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash): VerificationResult
    {
        // Verification procedure from https://www.w3.org/TR/webauthn/#tpm-attestation
        if (!($attStmt instanceof TpmAttestationStatement)) {
            throw new VerificationException('Expecting TpmAttestationStatement.');
        }

        // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
        // extract the contained fields.
        // -> this is done in TpmAttestationStatement

        // Verify that the public key specified by the parameters and unique fields of pubArea is identical to the
        // credentialPublicKey in the attestedCredentialData in authenticatorData.
        if (!$this->checkTpmPublicKeyMatchesAuthenticatorData($attStmt->getPubArea(), $authenticatorData)) {
            throw new VerificationException('Public key in pubArea does not match the key in authenticatorData');
        }

        // Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        $attToBeSigned = $authenticatorData->getRaw()->getBinaryString() . $clientDataHash;

        //Validate that certInfo is valid:
        if (!$this->checkCertInfo($attStmt, $attStmt->getAlgorithm(), $attToBeSigned)) {
            throw new VerificationException('TPM certInfo is not valid.');
        }

        // If x5c is present, this indicates that the attestation type is not ECDAA. In this case:
        $x5c = $attStmt->getCertificates();
        if ($x5c !== null) {
            return  $this->verifyX5C($x5c, $attStmt->getSignature(), $attStmt->getAlgorithm(), $attStmt->getRawCertInfo(), $authenticatorData);
        }

        // Either x5c or ECDAA is set, but only x5c is supported by this library. So if we reach this the statement
        // is unsupported.
        throw new UnsupportedException('ECDAA is not supported by this library.');
    }

    private function verifyX5c(array $x5c, ByteBuffer $signature, int $signatureAlgorithm, ByteBuffer $rawCertInfo, AuthenticatorData $authenticatorData): VerificationResult
    {
        // Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the
        // algorithm specified in alg.

        if (!isset($x5c[0])) {
            throw new VerificationException('Empty X5C in attestation.');
        }
        try {
            $cert = $this->certificateParser->parsePem($x5c[0]);

            $valid = $cert->verifySignature($rawCertInfo->getBinaryString(), $signature->getBinaryString(), $signatureAlgorithm);
        } catch (WebAuthnException $e) {
            throw new VerificationException('Failed to process attestation certificate.', 0, $e);
        }

        if (!$valid) {
            throw new VerificationException('Attestation signature is invalid.');
        }

        // Verify that aikCert meets the requirements in §8.3.1 TPM attestation statement certificate requirements.
        $this->checkCertRequirements($cert);

        // If aikCert contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the
        // value of this extension matches the aaguid in authenticatorData.
        FidoAaguidExtension::checkAaguidExtension($cert, $authenticatorData->getAaguid());

        // If successful, return attestation type AttCA and attestation trust path x5c.
        return new VerificationResult(AttestationType::ATT_CA, CertificateTrustPath::fromPemList($x5c));
    }

    private function checkTpmPublicKeyMatchesAuthenticatorData(TpmPublic $pubArea, AuthenticatorData $authData): bool
    {
        $key = $authData->getKey();
        $params = $pubArea->getParameters();
        if ($params instanceof TpmRsaParameters) {
            if (!($key instanceof RsaKey)) {
                return false;
            }

            if (!$params->getExponentAsBuffer()->equals($key->getExponent())) {
                return false;
            }

            if (!$pubArea->getUnique()->equals($key->getModulus())) {
                return false;
            }

            return true;
        }
        if ($params instanceof TpmEccParameters) {
            if (!($key instanceof Ec2Key)) {
                return false;
            }

            if (!$pubArea->getUnique()->equals($key->getUncompressedCoordinates())) {
                return false;
            }

            // TODO: CHECK CURVE ID
            throw new UnsupportedException('Not implemented yet');
            //return true;
        }
        throw new VerificationException('Unsupported TPM parameters type');
    }

    private function checkCertInfo(TpmAttestationStatement $attStmt, int $alorithm, string $attToBeSigned)
    {
        $certInfo = $attStmt->getCertInfo();
        $pubArea = $attStmt->getPubArea();

        $hash = new CoseHash($alorithm);

        // Verify that magic is set to TPM_GENERATED_VALUE.
        // Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        // -> both done by TpmAttest class.

        // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        if (!\hash_equals($certInfo->getExtraData()->getBinaryString(), $hash->hash($attToBeSigned))) {
            return false;
        }

        // Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3,
        // whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of
        // pubArea using the procedure specified in [TPMv2-Part1] section 16.
        if (!$pubArea->isValidPubInfoName($certInfo->getAttName())) {
            return false;
        }

        // Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2, i.e.,
        // qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.
        // -> not used here
        return true;
    }

    private function checkCertRequirements(CertificateDetailsInterface $cert)
    {
        // 8.3.1. TPM Attestation Statement Certificate Requirement

        // Version MUST be set to 3.
        $version = $cert->getCertificateVersion();
        if ($version !== CertificateDetails::VERSION_3) {
            throw new VerificationException(sprintf('Attestation certificate version value is %s but should be %s (version 3).', $version ?? 'null', CertificateDetails::VERSION_3));
        }

        // Subject field MUST be set to empty.
        if ($cert->getSubject() !== '') {
            throw new VerificationException('Subject of attestation certificate should be empty.');
        }

        // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
        $tpmManufacturer = $cert->getSubjectAlternateNameDN(self::OID_TCG_AT_TPM_MANUFACTURER);
        $cert->getSubjectAlternateNameDN(self::OID_TCG_AT_TPM_MODEL);
        $tpmVersion = $cert->getSubjectAlternateNameDN(self::OID_TCG_AT_TPM_VERSION);

        // Syntax is id:AABBCCDDEE where AABCCDDEE is the 4 byte manufacturer ID in hex.
        if (!preg_match('~^id:[0-9A-Fa-f]{8}$~', $tpmManufacturer, $match)) {
            throw new VerificationException('Invalid TPM manufacturer attribute in subjectAlternateName of attestation certificate.');
        }

        if (!preg_match('~^id:[0-9A-Fa-f]{2,}$~', $tpmVersion, $match)) {
            throw new VerificationException('Invalid TPM version attribute in subjectAlternateName of attestation certificate.');
        }

        // The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
        if (!$cert->extendedKeyUsageContains(self::OID_TCG_KP_AIK_CERTIFICATE)) {
            throw new VerificationException('Extended key usage of attestation certificate should contain tcg-kp-AIKCertificate.');
        }

        // The Basic Constraints extension MUST have the CA component set to false.
        if ($cert->isCA() !== false) {
            throw new VerificationException('Attestation certificate should not the CA basic constraint set to false.');
        }

        // An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension
        // [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through metadata services.
        // See, for example, the FIDO Metadata Service [FIDOMetadataService].
        // -> not handled here.
    }
}
