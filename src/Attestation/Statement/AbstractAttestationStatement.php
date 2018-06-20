<?php


namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Exception\ParseException;

abstract class AbstractAttestationStatement implements AttestationStatementInterface
{
    /**
     * @var string
     */
    private $formatId;

    public function __construct(AttestationObject $attestationObject, string $formatId)
    {
        $actualFormat = $attestationObject->getFormat();
        if ($actualFormat !== $formatId) {
            throw new ParseException(sprintf("Not expecting format '%s' but '%s'.", $actualFormat, $formatId));
        }
        $this->formatId = $formatId;
    }

    /**
     * @return string
     */
    public function getFormatId(): string
    {
        return $this->formatId;
    }
}
