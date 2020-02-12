<?php


namespace MadWizard\WebAuthn\Attestation\Registry;

use MadWizard\WebAuthn\Attestation\AttestationObjectInterface;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Verifier\AttestationVerifierInterface;
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
     * @param AttestationObjectInterface $attestationObject
     * @return AttestationStatementInterface
     * @throws DataValidationException
     */
    public function createStatement(AttestationObjectInterface $attestationObject) : AttestationStatementInterface;

    /**
     * Gets a reference to a verifier that verifies attestation statements of the format supported by this class.
     * @return AttestationVerifierInterface
     */
    public function getVerifier() : AttestationVerifierInterface;
}
