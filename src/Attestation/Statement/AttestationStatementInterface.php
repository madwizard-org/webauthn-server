<?php


namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;

interface AttestationStatementInterface
{
    /**
     * @return string
     */
    public function getFormatId(): string;

    public static function createFormat() : AttestationFormatInterface;
}
