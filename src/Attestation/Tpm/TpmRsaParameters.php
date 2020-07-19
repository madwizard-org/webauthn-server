<?php

namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Format\ByteBuffer;

class TpmRsaParameters implements KeyParametersInterface
{
    public const DEFAULT_EXPONENT = 65537;

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
    private $keyBits;

    /**
     * @var int
     */
    private $exponent;

    public function __construct(int $symmetric, int $scheme, int $keyBits, int $exponent)
    {
        $this->symmetric = $symmetric;
        $this->scheme = $scheme;
        $this->keyBits = $keyBits;
        $this->exponent = ($exponent === 0 ? self::DEFAULT_EXPONENT : $exponent);
    }

    public function getAlgorithm(): int
    {
        return TpmPublic::TPM_ALG_RSA;
    }

    public static function parse(ByteBuffer $buffer, int $offset, ?int &$endOffset): KeyParametersInterface
    {
        $symmetric = $buffer->getUint16Val($offset);
        $scheme = $buffer->getUint16Val($offset + 2);
        $keyBits = $buffer->getUint16Val($offset + 4);
        $exponent = $buffer->getUint16Val($offset + 6);
        $endOffset = $offset + 10;
        return new self($symmetric, $scheme, $keyBits, $exponent);
    }

    public function getSymmetric(): int
    {
        return $this->symmetric;
    }

    public function getScheme(): int
    {
        return $this->scheme;
    }

    public function getKeyBits(): int
    {
        return $this->keyBits;
    }

    public function getExponent(): int
    {
        return $this->exponent;
    }

    public function getExponentAsBuffer(): ByteBuffer
    {
        $raw = '';
        $e = $this->exponent;
        while ($e > 0) {
            $raw = chr($e & 0xFF) . $raw;
            $e >>= 8;
        }
        return new ByteBuffer($raw);
    }
}
