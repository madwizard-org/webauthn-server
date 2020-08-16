<?php

namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Exception\ParseException;

class NoneAttestationStatement extends AbstractAttestationStatement
{
    public const FORMAT_ID = 'none';

    public function __construct(AttestationObject $attestationObject)
    {
        parent::__construct($attestationObject, self::FORMAT_ID);

        $statement = $attestationObject->getStatement();
        if (\count($statement) !== 0) {
            throw new ParseException("Expecting empty map for 'none' attestation statement.");
        }
    }
}
