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

    public function __construct(ByteBuffer $x, ByteBuffer $y, int $curve)
    {
        parent::__construct(COSEAlgorithm::ES256);

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


        if ($curve === null || $x === null || $y === null) {
            throw new WebAuthnException('Missing data');
        }

        if (!\is_int($curve)) {
            throw new WebAuthnException('Wrong type');
        }

        if (!($x instanceof ByteBuffer && $y instanceof ByteBuffer)) {
            throw new WebAuthnException('Wrong type');
        }

        $key = new EC2Key($x, $y, $curve);
        $key->addCommonParams($data);
        return $key;
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
            "\x30\x59" . // SEQUENCE 0x59 bytes
            "\x30\x13" . // SEQUENCE 0x13 bytes
            "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01" . // OID 1.2.840.10045.2.1 ecPublicKey
            "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07" . // 1.2.840.10045.3.1.7 prime256v1
            "\x03\x42" . // BITSTREAM 0x42 bytes
            "\x00" . // Unused bits in bitstream
            "\x04" . // ECC uncompressed key format
            $this->x->getBinaryString() .
            $this->y->getBinaryString();


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
}
