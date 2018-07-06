<?php


namespace MadWizard\WebAuthn\Attestation\Registry;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Verifier\StatementVerifierInterface;
use MadWizard\WebAuthn\Exception\DataValidationException;

interface AttestationFormatInterface
{
    /**
     * Returns format ID for this attestation format. For example 'fido-u2f'.
     * @return string
     */
    public function getFormatId() : string;

    /**
     * Creates an attestation statement object from an attestation object. Should be called only for attestation
     * objects with format ID supported by this class (@see getFormatId).
     * @param AttestationObject $attestationObject
     * @return AttestationStatementInterface
     * @throws DataValidationException
     */
    public function createStatement(AttestationObject $attestationObject) : AttestationStatementInterface;

    /**
     * Gets a reference to a verifier that verifies attestation statements of the format supported by this class.
     * @return StatementVerifierInterface
     */
    public function getVerifier() : StatementVerifierInterface;
}
