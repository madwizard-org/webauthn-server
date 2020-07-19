<?php

namespace MadWizard\WebAuthn\Attestation\Statement;

interface AttestationStatementInterface
{
    public function getFormatId(): string;
}
