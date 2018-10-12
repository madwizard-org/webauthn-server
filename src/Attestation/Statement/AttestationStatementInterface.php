<?php


namespace MadWizard\WebAuthn\Attestation\Statement;

interface AttestationStatementInterface
{
    /**
     * @return string
     */
    public function getFormatId(): string;
}
