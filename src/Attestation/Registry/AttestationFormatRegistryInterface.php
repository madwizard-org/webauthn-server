<?php

namespace MadWizard\WebAuthn\Attestation\Registry;

use MadWizard\WebAuthn\Attestation\AttestationObjectInterface;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Verifier\AttestationVerifierInterface;
use MadWizard\WebAuthn\Exception\FormatNotSupportedException;

interface AttestationFormatRegistryInterface
{
    public function createStatement(AttestationObjectInterface $attestationObject): AttestationStatementInterface;

    /**
     * @param string $formatId
     * @return AttestationVerifierInterface
     * @throws FormatNotSupportedException
     */
    public function getVerifier(string $formatId): AttestationVerifierInterface;
}
