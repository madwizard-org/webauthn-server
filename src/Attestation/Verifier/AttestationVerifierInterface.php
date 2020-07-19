<?php

namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AuthenticatorDataInterface;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;

interface AttestationVerifierInterface
{
    public function verify(AttestationStatementInterface $attStmt, AuthenticatorDataInterface $authenticatorData, string $clientDataHash): VerificationResult;
}
