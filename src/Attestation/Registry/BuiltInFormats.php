<?php


namespace MadWizard\WebAuthn\Attestation\Registry;

use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;

final class BuiltInFormats
{
    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    /**
     * @return AttestationFormatInterface[]
     */
    public static function getSupportedFormats() : array
    {
        return [
            FidoU2fAttestationStatement::createFormat(),
            // PackedAttestationStatement::createFormat(),
            NoneAttestationStatement::createFormat()
            ];
    }
}
