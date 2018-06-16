<?php


namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Dom\COSEAlgorithm;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use function base64_encode;
use function chunk_split;
use function openssl_pkey_get_public;

class EC2Key extends COSEKey // TODO exceptions
{
    /**
     * @var ByteBuffer
     */
    private $x;

    /**
     * @var ByteBuffer
     */
    private $y;

    private $curve;

    public const CURVE_P256 = 1;

    /**
     *  EC identifier
     */
    private const KTP_CRV = -1;

    /**
     * X-coordinate
     */
    private const KTP_X = -2;

    /**
     * Y-coordinate
     */
    private const KTP_Y = -3;

    public function __construct(ByteBuffer $x, ByteBuffer $y, int $curve, int $algorithm)
    {
        parent::__construct($algorithm);

        if ($curve !== self::CURVE_P256) {
            throw new WebAuthnException('Unsupported curve'); // TODO: exception type
        }

        $coordLength = 32;

        if ($x->getLength() !== $coordLength || $y->getLength() !== $coordLength) {
            throw new WebAuthnException(sprintf('Expecting length %d for x and y', $coordLength));
        }



        $this->x = $x;
        $this->y = $y;
        $this->curve = $curve;
    }

    public static function fromCBORData(array $data) : EC2Key
    {
        $curve = $data[self::KTP_CRV] ?? null;
        $x = $data[self::KTP_X] ?? null;
        $y = $data[self::KTP_Y] ?? null;
        $alorithm = $data[self::COSE_KEY_PARAM_ALG] ?? null;

        //$algorithm = $data[self:;]
        // TODO: algorithm
        // TODO: disallow other fields

        if ($curve === null || $x === null || $y === null || $alorithm === null) {
            throw new WebAuthnException('Missing data');
        }

        if (!\is_int($alorithm)) {
            throw new WebAuthnException('Invalid algorithm type');
        }

        // TODO: disallow other fields

        if (!\is_int($curve)) {
            throw new WebAuthnException('Wrong type');
        }

        if (!($x instanceof ByteBuffer && $y instanceof ByteBuffer)) {
            throw new WebAuthnException('Wrong type');
        }

        return new EC2Key($x, $y, $curve, $alorithm);
    }

    /**
     * @return ByteBuffer
     */
    public function getX(): ByteBuffer
    {
        return $this->x;
    }

    /**
     * @return ByteBuffer
     */
    public function getY(): ByteBuffer
    {
        return $this->y;
    }

    /**
     * @return int
     */
    public function getCurve(): int
    {
        return $this->curve;
    }

    public function asPEM() : string
    {
        if ($this->curve !== self::CURVE_P256) {
            throw new WebAuthnException('Unsupported');
        }

        // DER encoded P256 curve
        $der =
            DER::sequence(
                DER::sequence(
                    DER::oid("\x2A\x86\x48\xCE\x3D\x02\x01") . // OID 1.2.840.10045.2.1 ecPublicKey
                    DER::oid("\x2A\x86\x48\xCE\x3D\x03\x01\x07")  // 1.2.840.10045.3.1.7 prime256v1
                ) .
                DER::bitString(
                    "\x04" . // ECC uncompressed key format
                    $this->x->getBinaryString() .
                    $this->y->getBinaryString()
                )
            );

        return '-----BEGIN PUBLIC KEY-----' . "\n" .
                chunk_split(base64_encode($der), 64, "\n") .
                '-----END PUBLIC KEY-----' . "\n";
    }

    public function verifySignature(ByteBuffer $data, ByteBuffer $signature) : bool
    {
        $publicKey = openssl_pkey_get_public($this->asPEM());
        if ($publicKey === false) {
            throw new WebAuthnException('Public key invalid');
        }

        if ($this->getAlgorithm() === COSEAlgorithm::ES256) {
            $algorithm = OPENSSL_ALGO_SHA256;
        } else {
            throw new WebAuthnException('Unsupported algorithm');
        }

        $verify = openssl_verify($data->getBinaryString(), $signature->getBinaryString(), $publicKey, $algorithm);
        if ($verify === 1) {
            return true;
        }
        if ($verify === 0) {
            return false;
        }

        throw new WebAuthnException('Failed to check signature');
    }

    protected function algorithmSupported(int $algorithm) : bool
    {
        return ($algorithm === COSEAlgorithm::ES256);
    }
}
