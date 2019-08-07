<?php


namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\Android\AndroidAttestationExtension;
use MadWizard\WebAuthn\Attestation\Android\AndroidExtensionParser;
use MadWizard\WebAuthn\Attestation\Android\AndroidExtensionParserInterface;
use MadWizard\WebAuthn\Attestation\Android\AuthorizationList;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AndroidKeyAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Crypto\CoseKeyInterface;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Pki\CertificateDetailsInterface;
use MadWizard\WebAuthn\Pki\CertificateParser;
use MadWizard\WebAuthn\Pki\CertificateParserInterface;

class AndroidKeyAttestationVerifier implements AttestationVerifierInterface
{
    private $certificateParser;

    private $extensionParser;

    public function __construct(?CertificateParserInterface $certificateParser = null, ?AndroidExtensionParserInterface $extensionParser = null)
    {
        $this->certificateParser = $certificateParser ?? new CertificateParser();
        $this->extensionParser = $extensionParser ?? new AndroidExtensionParser();
    }

    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        if (!($attStmt instanceof AndroidKeyAttestationStatement)) {
            throw new VerificationException('Expecting AndroidKeyAttestationStatement');
        }

        // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform
        // CBOR decoding on it to extract the contained fields.
        // -> this is done in AndroidKeyAttestationStatement


        $x5c = $attStmt->getCertificates();
        if (count($x5c) === 0) {
            throw new VerificationException('No certificates in chain');
        }
        $cert = $this->certificateParser->parsePem($x5c[0]);

        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using
        // the public key in the first certificate in x5c with the algorithm specified in alg.
        if (!$this->verifySignature($cert, $attStmt, $authenticatorData, $clientDataHash)) {
            throw new VerificationException('Signature invalid');
        }

        // Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
        // attestedCredentialData in authenticatorData.

        if (!$this->certificateKeyMatches($cert, $authenticatorData->getKey())) {
            throw new VerificationException('Public key of first certificate in chain does not match the public key from the authenticator data.');
        }


        $data = $cert->getExtensionData(AndroidAttestationExtension::OID);
        if ($data === null) {
            throw new VerificationException('Missing Android attestation extension.');
        }
        $ext = $this->extensionParser->parseAttestationExtension($data);

        $this->checkAndroidKeyExtension($ext, $clientDataHash);

        //  If successful, return implementation-specific values representing attestation type Basic and attestation trust path x5c.
        return new VerificationResult(AttestationType::BASIC, new CertificateTrustPath($x5c));
    }

    private function checkAndroidKeyExtension(AndroidAttestationExtension $ext, string $clientDataHash)
    {
        // Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.

        if (!\hash_equals($ext->getChallenge()->getBinaryString(), $clientDataHash)) {
            throw new VerificationException('AttestationChallenge in Android attestation extension does not match clientDataHash.');
        }

        //  Verify the following using the appropriate authorization list from the attestation certificate extension data:
        //   The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
        $seAuth = $ext->getSoftwareEnforcedAuthList();
        $teeAuth = $ext->getTeeEnforcedAuthList();
        if ($seAuth->hasAllApplications() || $teeAuth->hasAllApplications()) {
            throw new VerificationException('Invalid Android attestation extension: allApplication fields cannot be present in softwareEnforced or teeEnforced authorization list.');
        }

        //  For the following, use only the teeEnforced authorization list if the RP wants to accept only keys from a trusted execution environment, otherwise use the union of teeEnforced and softwareEnforced.

        //  - The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
        //  - The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.


        $seValid = ($seAuth->hasPurpose(AuthorizationList::KM_PURPOSE_SIGN) && $seAuth->getOrigin() === AuthorizationList::KM_ORIGIN_GENERATED);
        $teeValid = ($teeAuth->hasPurpose(AuthorizationList::KM_PURPOSE_SIGN) && $teeAuth->getOrigin() === AuthorizationList::KM_ORIGIN_GENERATED);

        // TODO: how to provide this as an option?
        if (!($seValid || $teeValid)) {
            throw new VerificationException('Invalid Android attestation extension: no acceptable authorization lists.');
        }
    }

    private function verifySignature(CertificateDetailsInterface $cert, AndroidKeyAttestationStatement $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash): bool
    {
        try {
            $verificationData = $authenticatorData->getRaw()->getBinaryString() . $clientDataHash;
            return $cert->verifySignature($verificationData, $attStmt->getSignature()->getBinaryString(), $attStmt->getAlgorithm());
        } catch (WebAuthnException $e) {
            throw new VerificationException('Failed to verify signature', 0, $e);
        }
    }

    private function certificateKeyMatches(CertificateDetailsInterface $cert, CoseKeyInterface $key): bool
    {
        // Compare DER encodings of both keys to ensure they are equal.
        // By definition there is always only one exact DER encoding for a public key.
        $certKeyDer = $cert->getPublicKeyDer();
        $keyDer = $key->asDer();
        return hash_equals($certKeyDer, $keyDer);
    }
}
