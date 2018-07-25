<?php


namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\PackedAttestationStatement;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\ByteBuffer;

class PackedStatementVerifier implements StatementVerifierInterface
{
    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        // Verification procedure from https://www.w3.org/TR/webauthn/#packed-attestation

        if (!($attStmt instanceof PackedAttestationStatement)) {
            throw new VerificationException('Expecting PackedAttestationStatement');
        }

        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it
        // to extract the contained fields.
        // -> This is done in PackedAttestationStatement

        // 2. If x5c is present, this indicates that the attestation type is not ECDAA.
        $x5c = $attStmt->getCertificates();
        if ($x5c !== null) {
            return $this->verifyX5C($x5c, $authenticatorData, $clientDataHash);
        }


        // 3. If ecdaaKeyId is present, then the attestation type is ECDAA. In this case:
        $ecdaaKeyId = $attStmt->getEcdaaKeyId();
        if ($ecdaaKeyId !== null) {
            return $this->verifyEcdaa($ecdaaKeyId, $authenticatorData, $clientDataHash);
        }

        // 4. If neither x5c nor ecdaaKeyId is present, self attestation is in use.
        return $this->verifySelf($attStmt->getAlgorithm(), $authenticatorData, $clientDataHash);
    }

    private function verifyX5c(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in x5c with the algorithm specified in alg.
        // Verify that x5c meets the requirements in §8.2.1 Packed attestation statement certificate requirements.
        // If x5c contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
        // If successful, return attestation type Basic and attestation trust path x5c.

        // TODO: implement
        throw new UnsupportedException('TODO');
    }

    private function verifyEcdaa(ByteBuffer $ecdaaKeyId, AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId (see [FIDOEcdaaAlgorithm]).
        // If successful, return attestation type ECDAA and attestation trust path ecdaaKeyId.
        throw new UnsupportedException('ECDAA is not supported by this library.');
    }

    private function verifySelf(int $algorithm, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
        $key = $authenticatorData->getKey();
        if ($key === null) {
            throw new VerificationException('No key in authenticator data.');
        }
        if ($key->getAlgorithm() !== $algorithm) {
            throw new VerificationException(sprintf('Algorithm in packed attestation statement (%d) should match public key algorithm (%d)', $algorithm, $key->getAlgorithm()));
        }

        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
        // If successful, return attestation type Self and empty attestation trust path.
        // TODO: implement

        throw new UnsupportedException('TODO');
    }
}
