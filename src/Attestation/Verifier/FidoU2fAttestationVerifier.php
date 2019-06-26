<?php


namespace MadWizard\WebAuthn\Attestation\Verifier;

use const OPENSSL_ALGO_SHA256;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Crypto\Ec2Key;
use MadWizard\WebAuthn\Exception\VerificationException;
use function openssl_free_key;
use function openssl_pkey_get_details;
use function openssl_verify;

class FidoU2fAttestationVerifier extends AbstractAttestationVerifier
{
    private const ZERO_AAGUID = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        if (!($attStmt instanceof FidoU2fAttestationStatement)) {
            throw new VerificationException('Expecting FidoU2fAttestationStatement');
        }

        // AAGUID for U2F should be zeroes (not in WebAuthn spec but in FIDO2 CTAP specs and FIDO conformance tools)
        if ($authenticatorData->getAaguid()->getBinaryString() !== self::ZERO_AAGUID) {
            throw new VerificationException('AAGUID should be zeroed for U2F attestations.');
        }

        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding
        //    on it to extract the contained fields.
        // -> This is done in FidoU2fAttestationStatement

        // 2
        $key = $this->checkAttCertKey($attStmt);

        try {
            // 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey
            //    from authenticatorData.attestedCredentialData.
            $rpIdHash = $authenticatorData->getRpIdHash();
            $credentialId = $authenticatorData->getCredentialId();
            if ($credentialId === null) {
                throw new VerificationException('No credential id available.');
            }

            // 4
            $publicKeyU2f = $this->getPublicKeyU2f($authenticatorData);

            // 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
            $verificationData = "\x00" . $rpIdHash->getBinaryString() . $clientDataHash . $credentialId->getBinaryString() . $publicKeyU2f;

            // 6. Verify the sig using verificationData and certificate public key per [SEC1].
            $result = openssl_verify(
                $verificationData,
                $attStmt->getSignature()->getBinaryString(),
                $key,
                OPENSSL_ALGO_SHA256
            );

            if ($result === 1) {
                // 7. If successful, return attestation type Basic with the attestation trust path set to x5c.
                return new VerificationResult(AttestationType::BASIC, new CertificateTrustPath($attStmt->getCertificates()));
            }

            if ($result === 0) {
                throw new VerificationException('Signature invalid.');
            }

            throw new VerificationException('Failed to check signature');
        } finally {
            openssl_free_key($key);
        }
    }

    private function checkAttCertKey(FidoU2fAttestationStatement $attStmt)
    {
        // 2. Check that x5c has exactly one element and let attCert be that element. Let certificate public key
        //    be the public key conveyed by attCert. If certificate public key is not an Elliptic Curve (EC) public
        //    key over the P-256 curve, terminate this algorithm and return an appropriate error.
        $certificates = $attStmt->getCertificates();
        if (count($certificates) === 0) {
            throw new VerificationException('FIDO-U2F statements should contain exactly one certificate.');
        }

        $attCert = $certificates[0];

        $x509 = openssl_pkey_get_public($attCert);
        if ($x509 === false) {
            throw new VerificationException('Failed to parse x509 public key.');
        }

        $details = openssl_pkey_get_details($x509);

        if ($details === false || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            throw new VerificationException('Expecting first certificate to have P-256 EC key.');
        }
        return $x509;
    }

    private function getPublicKeyU2f(AuthenticatorData $authData) : string
    {
        // 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to Raw ANSI X9.62 public
        //    key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
        //
        //      Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey,
        //      and confirm its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm
        //
        //      Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey,
        //      and confirm its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm
        //      and return an appropriate error.
        //

        $credentialPublicKey = $authData->getKey();

        if (!($credentialPublicKey instanceof Ec2Key)) {
            throw new VerificationException('Public key is not EC2 key.');
        }

        $x = $credentialPublicKey->getX();
        $y = $credentialPublicKey->getY();

        if ($x->getLength() !== 32 || $y->getLength() !== 32) {
            throw new VerificationException('Unexpected key size.');
        }

        // Let publicKeyU2F be the concatenation 0x04 || x || y. This signifies uncompressed ECC key format.
        return "\x04" . $x->getBinaryString() . $y->getBinaryString();
    }
}
