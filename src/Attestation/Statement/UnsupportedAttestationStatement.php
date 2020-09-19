<?php

namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;

class UnsupportedAttestationStatement extends AbstractAttestationStatement
{
    public function __construct(AttestationObject $attestationObject)
    {
        parent::__construct($attestationObject, $attestationObject->getFormat());
    }
}
