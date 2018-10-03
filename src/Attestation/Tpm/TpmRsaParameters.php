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

    public static function parse(ByteBuffer $buffer, int $offset, ?int &$endOffset) : KeyParametersInterface
    {
        $symmetric = $buffer->getUint16Val($offset);
        $scheme = $buffer->getUint16Val($offset + 2);
        $keyBits = $buffer->getUint16Val($offset + 4);
        $exponent = $buffer->getUint16Val($offset + 6);
        $endOffset = $offset + 10;
        return new self($symmetric, $scheme, $keyBits, $exponent);
    }

    /**
     * @return int
     */
    public function getSymmetric(): int
    {
        return $this->symmetric;
    }

    /**
     * @return int
     */
    public function getScheme(): int
    {
        return $this->scheme;
    }

    /**
     * @return int
     */
    public function getKeyBits(): int
    {
        return $this->keyBits;
    }

    /**
     * @return int
     */
    public function getExponent(): int
    {
        return $this->exponent;
    }
}
