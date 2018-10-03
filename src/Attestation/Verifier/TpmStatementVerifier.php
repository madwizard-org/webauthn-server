<?php


namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\TpmAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\EmptyTrustPath;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\PKI\CertificateDetails;

class TpmStatementVerifier implements StatementVerifierInterface
{
    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        if (!($attStmt instanceof TpmAttestationStatement)) {
            throw new VerificationException('Expecting TpmAttestationStatement.');
        }
        /*
        $algorithm = $attStmt->getAlgorithm();
        $signature = $attStmt->getSignature();

        $x5c = $attStmt->getCertificates();


        $cert = CertificateDetails::fromPEM($x5c[0]);


        $verificationData = $attStmt->getRawCertInfo()->getBinaryString();

        $valid = $cert->verifySignature($verificationData, $signature->getBinaryString(), $algorithm);
        return new VerificationResult(AttestationType::NONE, new EmptyTrustPath());
        */
        throw new UnsupportedException('Not implemented yet');
    }
}
