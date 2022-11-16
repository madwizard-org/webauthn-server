<?php

namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Format\ByteBuffer;

class TpmEccPublicId implements KeyPublicIdInterface
{
    use TpmStructureTrait;

    /**
     * @var ByteBuffer
     */
    private $x;

    /**
     * @var ByteBuffer
     */
    private $y;

    private function __construct(ByteBuffer $x, ByteBuffer $y)
    {
        $this->x = $x;
        $this->y = $y;
    }

    public function getX(): ByteBuffer
    {
        return $this->x;
    }

    public function getY(): ByteBuffer
    {
        return $this->y;
    }

    public static function parse(ByteBuffer $buffer, int $offset, ?int &$endOffset): KeyPublicIdInterface
    {
        $x = self::readLengthPrefixed($buffer, $offset);
        $y = self::readLengthPrefixed($buffer, $offset);
        $endOffset = $offset;
        return new self($x, $y);
    }
}
