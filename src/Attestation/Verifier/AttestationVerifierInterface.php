<?php

namespace MadWizard\WebAuthn\Attestation\Verifier;

use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;

interface AttestationVerifierInterface
{
    public function verify(AttestationStatementInterface $attStmt, AuthenticatorData $authenticatorData, string $clientDataHash): VerificationResult;

    public function getSupportedFormat(): AttestationFormatInterface;
}
