<?php

namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface KeyPublicIdInterface
{
    public static function parse(ByteBuffer $buffer, int $offset, ?int &$endOffset): self;
}
