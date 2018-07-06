<?php


namespace MadWizard\WebAuthn\Attestation\Registry;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Verifier\StatementVerifierInterface;

class BuiltInAttestationFormat implements AttestationFormatInterface
{
    /**
     * @var string
     */
    private $formatId;

    /**
     * @var string
     */
    private $statementClass;

    /**
     * @var string
     */
    private $verifierClass;

    /**
     * @var StatementVerifierInterface|null
     */
    private $verifier;

    public function __construct(string $formatId, string $statementClass, string $verifierClass)
    {
        $this->formatId = $formatId;
        $this->statementClass = $statementClass;
        $this->verifierClass = $verifierClass;
    }

    public function getFormatId(): string
    {
        return $this->formatId;
    }

    public function createStatement(AttestationObject $attestationObject): AttestationStatementInterface
    {
        $class = $this->statementClass;
        return new $class($attestationObject);
    }

    public function getVerifier(): StatementVerifierInterface
    {
        $verifierClass = $this->verifierClass;
        if ($this->verifier === null) {
            $this->verifier = new $verifierClass();
        }
        return $this->verifier;
    }
}
