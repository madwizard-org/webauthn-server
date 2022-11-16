<?php

namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Format\ByteBuffer;

class TpmRsaPublicId implements KeyPublicIdInterface
{
    use TpmStructureTrait;

    /**
     * @var ByteBuffer
     */
    private $modulus;

    private function __construct(ByteBuffer $modulus)
    {
        $this->modulus = $modulus;
    }

    public function getModulus(): ByteBuffer
    {
        return $this->modulus;
    }

    public static function parse(ByteBuffer $buffer, int $offset, ?int &$endOffset): KeyPublicIdInterface
    {
        $modulus = self::readLengthPrefixed($buffer, $offset);
        $endOffset = $offset;
        return new self($modulus);
    }
}
