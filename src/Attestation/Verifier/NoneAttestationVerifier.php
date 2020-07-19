<?php

namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorDataInterface;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\EmptyTrustPath;
use MadWizard\WebAuthn\Exception\VerificationException;

class NoneAttestationVerifier extends AbstractAttestationVerifier
{
    public function verify(AttestationStatementInterface $attStmt, AuthenticatorDataInterface $authenticatorData, string $clientDataHash): VerificationResult
    {
        if (!($attStmt instanceof NoneAttestationStatement)) {
            throw new VerificationException('Expecting NoneAttestationStatement.');
        }
        return new VerificationResult(AttestationType::NONE, new EmptyTrustPath());
    }
}
