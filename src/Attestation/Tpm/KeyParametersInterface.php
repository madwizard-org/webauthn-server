<?php


namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface KeyParametersInterface
{
    public function getAlgorithm() : int;

    public static function parse(ByteBuffer $buffer, int $offset, int &$endOffset) : KeyParametersInterface;
}
