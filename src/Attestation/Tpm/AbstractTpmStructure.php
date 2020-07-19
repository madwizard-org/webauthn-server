<?php

namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Format\ByteBuffer;

abstract class AbstractTpmStructure
{
    protected function readLengthPrefixed(ByteBuffer $buffer, int &$offset): ByteBuffer
    {
        $len = $buffer->getUint16Val($offset);
        $data = $buffer->getBytes($offset + 2, $len);
        $offset += (2 + $len);
        return new ByteBuffer($data);
    }

    protected function readFixed(ByteBuffer $buffer, int &$offset, int $length): ByteBuffer
    {
        $data = $buffer->getBytes($offset, $length);
        $offset += $length;
        return new ByteBuffer($data);
    }
}
