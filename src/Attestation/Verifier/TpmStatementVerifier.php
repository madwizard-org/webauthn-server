<?php


namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\TpmAttestationStatement;
use MadWizard\WebAuthn\Attestation\Tpm\TpmEccParameters;
use MadWizard\WebAuthn\Attestation\Tpm\TpmPublic;
use MadWizard\WebAuthn\Attestation\Tpm\TpmRsaParameters;
use MadWizard\WebAuthn\Crypto\Ec2Key;
use MadWizard\WebAuthn\Crypto\RsaKey;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Pki\CertificateParserInterface;

class TpmStatementVerifier implements StatementVerifierInterface
{
    /**
     * @var CertificateParserInterface
     */
    private $certificateParser;

    public function __construct(CertificateParserInterface $certificateParser)
    {
        $this->certificateParser = $certificateParser;
    }

    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
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
        if (!$this->checkTpmPublicKeyMatchesAuthenticatorData($attStmt->getTpmPublic(), $authenticatorData)) {
            throw new VerificationException('Public key in pubArea does not match the key in authenticatorData');
        }


        //
        //Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        //
        //Validate that certInfo is valid:
        //
        //Verify that magic is set to TPM_GENERATED_VALUE.
        //
        //Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        //
        //Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        //
        //Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
        //
        //Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.
        //
        //If x5c is present, this indicates that the attestation type is not ECDAA. In this case:
        //
        //Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
        //
        //Verify that aikCert meets the requirements in §8.3.1 TPM attestation statement certificate requirements.
        //
        //If aikCert contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
        //
        //If successful, return attestation type AttCA and attestation trust path x5c.
        //
        //If ecdaaKeyId is present, then the attestation type is ECDAA.
        //
        //Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo (see [FIDOEcdaaAlgorithm]).
        //
        //If successful, return attestation type ECDAA and the identifier of the ECDAA-Issuer public key ecdaaKeyId.


        throw new UnsupportedException('Not implemented yet');
    }

    private function checkTpmPublicKeyMatchesAuthenticatorData(TpmPublic $pubArea, AuthenticatorData $authData) : bool
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
            throw new VerificationException('Not implemented yet');

            //return true;
        }
        throw new VerificationException('Unsupported TPM parameters type');
    }
}
