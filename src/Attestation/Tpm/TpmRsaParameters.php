<?php

namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Format\ByteBuffer;

/**
 * Represents TPMS_RSA_PARMS structure.
 */
final class TpmRsaParameters implements KeyParametersInterface
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
        if ($symmetric !== TpmPublic::TPM_ALG_NULL) {
            // Values other than TPM_ALG_NULL may be followed by additional fields (in TPMT_SYM_DEF_OBJECT)
            // so bail out if symmetric algorithm is not null
            throw new UnsupportedException('Only TPM_ALG_NULL supported for symmetric field in TPMS_RSA_PARMS');
        }
        $scheme = $buffer->getUint16Val($offset + 2);
        if ($scheme !== TpmPublic::TPM_ALG_NULL) {
            // Values other than TPM_ALG_NULL may be followed by additional fields (in TPMT_RSA_SCHEME)
            // so bail out if scheme algorithm is not null
            throw new UnsupportedException('Only TPM_ALG_NULL supported for scheme field in TPMS_RSA_PARMS');
        }        $keyBits = $buffer->getUint16Val($offset + 4);
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
