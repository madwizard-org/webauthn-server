<?php


namespace MadWizard\WebAuthn\Attestation\Registry;

use MadWizard\WebAuthn\Attestation\Statement\AndroidKeyAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\PackedAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\TpmAttestationStatement;

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
            PackedAttestationStatement::createFormat(),
            NoneAttestationStatement::createFormat(),
            TpmAttestationStatement::createFormat(),
            AndroidKeyAttestationStatement::createFormat(),
            ];
    }
}
