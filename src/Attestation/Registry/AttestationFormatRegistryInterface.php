<?php

namespace MadWizard\WebAuthn\Attestation\Registry;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Verifier\StatementVerifierInterface;

interface AttestationFormatRegistryInterface
{
    public function createStatement(AttestationObject $attestationObject): AttestationStatementInterface;

    public function getVerifier(string $formatId): StatementVerifierInterface;
}
