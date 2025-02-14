<?php

namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Format\ByteBuffer;

/**
 * Represents TPMPS_ECC_PARMS structure.
 */
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

    public const TPM_ECC_NIST_P256 = 0x0003;

    public const TPM_ECC_NIST_P384 = 0x0004;

    public const TPM_ECC_NIST_P521 = 0x0005;

    public const TPM_ECC_BN_P256 = 0x0010;

    public const TPM_ECC_SM2_P256 = 0x0020;

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

    public static function parse(ByteBuffer $buffer, int $offset, ?int &$endOffset): KeyParametersInterface
    {
        $symmetric = $buffer->getUint16Val($offset);
        if ($symmetric !== TpmPublic::TPM_ALG_NULL) {
            // Values other than TPM_ALG_NULL may be followed by additional fields (in TPMT_SYM_DEF_OBJECT)
            // so bail out if symmetric algorithm is not null
            throw new UnsupportedException('Only TPM_ALG_NULL supported for symmetric field in TPMPS_ECC_PARMS');
        }
        $scheme = $buffer->getUint16Val($offset + 2);
        if ($scheme !== TpmPublic::TPM_ALG_NULL) {
            // Values other than TPM_ALG_NULL may be followed by additional fields (in TPMT_ECC_SCHEME)
            // so bail out if scheme algorithm is not null
            throw new UnsupportedException('Only TPM_ALG_NULL supported for scheme field in TPMPS_ECC_PARMS');
        }
        $curveId = $buffer->getUint16Val($offset + 4);
        $kdf = $buffer->getUint16Val($offset + 6);
        if ($kdf !== TpmPublic::TPM_ALG_NULL) {
            // Values other than TPM_ALG_NULL may be followed by additional fields (in TPMT_KDF_SCHEME+)
            // so bail out if kdf algorithm is not null
            throw new UnsupportedException('Only TPM_ALG_NULL supported for kdf field in TPMPS_ECC_PARMS');
        }
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
