<?php

namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\UnsupportedAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\EmptyTrustPath;
use MadWizard\WebAuthn\Exception\VerificationException;

class UnsupportedAttestationVerifier implements AttestationVerifierInterface
{
    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash): VerificationResult
    {
        if (!($attStmt instanceof UnsupportedAttestationStatement)) {
            throw new VerificationException('Expecting UnsupportedAttestationStatement.');
        }
        return new VerificationResult(AttestationType::NONE, new EmptyTrustPath());
    }
}
