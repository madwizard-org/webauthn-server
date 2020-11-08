<?php

namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Format\ByteBuffer;

final class TpmEccParameters implements KeyParametersInterface
{
    /**
     * @var int
     */
    private $symmetric;

    /**
     * @var int
     */
    private $scheme;

    /**
     * @var int
     */
    private $curveId;

    /**
     * @var int
     */
    private $kdf;

    public function __construct(int $symmetric, int $scheme, int $curveId, int $kdf)
    {
        $this->symmetric = $symmetric;
        $this->scheme = $scheme;
        $this->curveId = $curveId;
        $this->kdf = $kdf;
    }

    public function getAlgorithm(): int
    {
        return TpmPublic::TPM_ALG_ECC;
    }

    public static function parse(ByteBuffer $buffer, int $offset, int &$endOffset): KeyParametersInterface
    {
        $symmetric = $buffer->getUint16Val($offset);
        $scheme = $buffer->getUint16Val($offset + 2);
        $curveId = $buffer->getUint16Val($offset + 4);
        $kdf = $buffer->getUint16Val($offset + 6);
        $endOffset = $offset + 8;
        return new self($symmetric, $scheme, $curveId, $kdf);
    }

    public function getSymmetric(): int
    {
        return $this->symmetric;
    }

    public function getScheme(): int
    {
        return $this->scheme;
    }

    public function getCurveId(): int
    {
        return $this->curveId;
    }

    public function getKdf(): int
    {
        return $this->kdf;
    }
}
