<?php

namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborEncoder;
use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Format\DataValidator;
use SodiumException;

class OkpKey extends CoseKey
{
    public const CURVE_ED25519 = 6;

    private const KTP_CRV = -1;

    private const KTP_X = -2;

    private const SUPPORTED_CURVES = [self::CURVE_ED25519];

    private const CURVE_KEY_LENGTH = [
        self::CURVE_ED25519 => 32,
    ];

    /**
     * @var ByteBuffer X coordinate of key
     */
    private $x;

    /**
     * @var int
     */
    private $curve;

    public function __construct(ByteBuffer $x, int $curve, int $algorithm)
    {
        parent::__construct($algorithm);

        if (!in_array($curve, self::SUPPORTED_CURVES, true)) {
            throw new UnsupportedException('Unsupported curve');
        }

        $coordLength = self::CURVE_KEY_LENGTH[$curve];

        if ($x->getLength() !== $coordLength) {
            throw new WebAuthnException(sprintf('Expecting length %d for x', $coordLength));
        }
        $this->x = $x;
        $this->curve = $curve;
    }

    public function getCbor(): ByteBuffer
    {
        $map = [
            self::COSE_KEY_PARAM_KTY => self::COSE_KTY_OKP,
            self::COSE_KEY_PARAM_ALG => $this->getAlgorithm(),
            self::KTP_CRV => $this->curve,
            self::KTP_X => $this->x,
        ];

        return new ByteBuffer(CborEncoder::encodeMap(CborMap::fromArray($map)));
    }

    public function getCurve(): int
    {
        return $this->curve;
    }

    public function getX(): ByteBuffer
    {
        return $this->x;
    }

    public function verifySignature(ByteBuffer $data, ByteBuffer $signature): bool
    {
        if ($this->curve === self::CURVE_ED25519) {
            try {
                return sodium_crypto_sign_verify_detached(
                    $signature->getBinaryString(),
                    $data->getBinaryString(),
                    $this->x->getBinaryString()
                );
            } catch (SodiumException $e) {
                throw new VerificationException('Failed to verify signature: ' . $e->getMessage(), 0, $e);
            }
        }
        throw new UnsupportedException('Unsupported curve');
    }

    protected function algorithmSupported(int $algorithm): bool
    {
        return $algorithm === CoseAlgorithm::EDDSA;
    }

    public function asDer(): string
    {
        if ($this->curve !== self::CURVE_ED25519) {
            throw new UnsupportedException('Unsupported curve.');
        }
        return
            Der::sequence(
                Der::sequence(
                    Der::oid("\x2B\x65\x70") // OID 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
                ) .
                Der::bitString(
                    $this->x->getBinaryString()
                )
            );
    }

    public static function fromCborData(CborMap $data): OkpKey
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
            ]
        );

        $curve = $data->get(self::KTP_CRV);
        $x = $data->get(self::KTP_X);
        $algorithm = $data->get(self::COSE_KEY_PARAM_ALG);

        return new OkpKey($x, $curve, $algorithm);
    }
}
