<?php

namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborEncoder;
use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Format\DataValidator;

class Ec2Key extends CoseKey // TODO exceptions
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

    /**
     * NIST P-256 also known as secp256r1.
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
     */
    public const CURVE_P256 = 1;

    /**
     * NIST P-256 also known as secp256r1.
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
     */
    public const CURVE_P384 = 2;

    /**
     * NIST P-521 also known as secp256r1.
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
     */
    public const CURVE_P521 = 3;

    private const SUPPORTED_CURVES = [
        self::CURVE_P256,
        self::CURVE_P384,
        self::CURVE_P521,
    ];

    /**
     *  EC identifier.
     */
    private const KTP_CRV = -1;

    /**
     * X-coordinate.
     */
    private const KTP_X = -2;

    /**
     * Y-coordinate.
     */
    private const KTP_Y = -3;

    private const SUPPORTED_ALGORITHMS = [
        CoseAlgorithm::ES256,
        CoseAlgorithm::ES384,
        CoseAlgorithm::ES512,
    ];

    private const CURVE_KEY_LENGTH = [
        self::CURVE_P256 => 32,
        self::CURVE_P384 => 48,
        self::CURVE_P521 => 66,
    ];

    private const CURVE_OID = [
        // 1.2.840.10045.3.1.7 NIST P-256 / secp256r1
        self::CURVE_P256 => "\x2A\x86\x48\xCE\x3D\x03\x01\x07",

        // 1.3.132.0.34 NIST P-384 / secp384r1
        self::CURVE_P384 => "\x2B\x81\x04\x00\x22",

        // 1.3.132.0.35 NIST P-521 / secp521r1
        self::CURVE_P521 => "\x2B\x81\x04\x00\x23",
    ];

    public function __construct(ByteBuffer $x, ByteBuffer $y, int $curve, int $algorithm)
    {
        parent::__construct($algorithm);

        if (!in_array($curve, self::SUPPORTED_CURVES, true)) {
            throw new UnsupportedException('Unsupported curve');
        }

        $coordLength = self::CURVE_KEY_LENGTH[$curve];

        if ($x->getLength() !== $coordLength || $y->getLength() !== $coordLength) {
            throw new WebAuthnException(sprintf('Expecting length %d for x and y', $coordLength));
        }

        $this->x = $x;
        $this->y = $y;
        $this->curve = $curve;
    }

    public static function fromCborData(CborMap $data): Ec2Key
    {
        // Note: leading zeroes in X and Y coordinates are preserved in CBOR
        // See RFC8152 13.1.1. Double Coordinate Curves
        DataValidator::checkMap(
            $data,
            [
                self::COSE_KEY_PARAM_KTY => 'integer',
                self::KTP_CRV => 'integer',
                self::COSE_KEY_PARAM_ALG => 'integer',
                self::KTP_X => ByteBuffer::class,
                self::KTP_Y => ByteBuffer::class,
            ]
        );

        $curve = $data->get(self::KTP_CRV);
        $x = $data->get(self::KTP_X);
        $y = $data->get(self::KTP_Y);
        $alorithm = $data->get(self::COSE_KEY_PARAM_ALG);

        return new Ec2Key($x, $y, $curve, $alorithm);
    }

    public function getX(): ByteBuffer
    {
        return $this->x;
    }

    public function getY(): ByteBuffer
    {
        return $this->y;
    }

    public function getCurve(): int
    {
        return $this->curve;
    }

    public function asDer(): string
    {
        // DER encoded P256 curve
        return
            Der::sequence(
                Der::sequence(
                    Der::oid("\x2A\x86\x48\xCE\x3D\x02\x01") . // OID 1.2.840.10045.2.1 ecPublicKey
                    Der::oid($this->getCurveOid())
                ) .
                Der::bitString(
                    $this->getUncompressedCoordinates()->getBinaryString()
                )
            );
    }

    public function asPem(): string
    {
        return Der::pem('PUBLIC KEY', $this->asDER());
    }

    private function getCurveOid(): string
    {
        return self::CURVE_OID[$this->curve];
    }

    public function getCbor(): ByteBuffer
    {
        $map = [
            self::COSE_KEY_PARAM_KTY => self::COSE_KTY_EC2,
            self::COSE_KEY_PARAM_ALG => $this->getAlgorithm(),
            self::KTP_CRV => $this->curve,
            self::KTP_X => $this->x,
            self::KTP_Y => $this->y,
        ];
        return new ByteBuffer(CborEncoder::encodeMap($map));
    }

    public function getUncompressedCoordinates(): ByteBuffer
    {
        $data = "\x04" . // ECC uncompressed key format
            $this->x->getBinaryString() .
            $this->y->getBinaryString();
        return new ByteBuffer($data);
    }

    public function verifySignature(ByteBuffer $data, ByteBuffer $signature): bool
    {
        $verifier = new OpenSslVerifier($this->getAlgorithm());
        return $verifier->verify($data->getBinaryString(), $signature->getBinaryString(), $this->asPem());
    }

    protected function algorithmSupported(int $algorithm): bool
    {
        return in_array($algorithm, self::SUPPORTED_ALGORITHMS, true);
    }
}
