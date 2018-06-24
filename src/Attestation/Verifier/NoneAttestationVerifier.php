<?php


namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\EmptyTrustPath;
use MadWizard\WebAuthn\Exception\VerificationException;

class NoneAttestationVerifier implements StatementVerifierInterface
{
    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash) : VerificationResult
    {
        if (!($attStmt instanceof NoneAttestationStatement)) {
            throw new VerificationException('Expecting NoneAttestationStatement.');
        }
        return new VerificationResult(AttestationType::NONE, new EmptyTrustPath());
    }
}
