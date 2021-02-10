<?php

namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborEncoder;
use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Format\DataValidator;

class RsaKey extends CoseKey
{
    /**
     * RSA modulus n key type parameter (key type 3, RSA).
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    private const KTP_N = -1;

    /**
     * RSA exponent e key type parameter (key type 3, RSA).
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    private const KTP_E = -2;

    /**
     * RSA modulus. Unsigned integer value represented as binary buffer with leading zero bytes removed.
     *
     * @var ByteBuffer
     */
    private $modulus;

    /**
     * RSA exponent. Unsigned integer value represented as binary buffer with leading zero bytes removed.
     *
     * @var ByteBuffer
     */
    private $exponent;

    private const SUPPORTED_ALGORITHMS = [
        CoseAlgorithm::RS256,
        CoseAlgorithm::RS384,
        CoseAlgorithm::RS512,
        CoseAlgorithm::RS1,
    ];

    public function __construct(ByteBuffer $modulus, ByteBuffer $exponent, int $algorithm)
    {
        parent::__construct($algorithm);
        $this->modulus = $this->compactIntegerBuffer($modulus);
        $this->exponent = $this->compactIntegerBuffer($exponent);
    }

    public static function fromCborData(CborMap $data): RsaKey
    {
        DataValidator::checkMap(
            $data,
            [
                self::COSE_KEY_PARAM_KTY => 'integer',
                self::COSE_KEY_PARAM_ALG => 'integer',
                self::KTP_N => ByteBuffer::class,
                self::KTP_E => ByteBuffer::class,
            ]
        );

        $algorithm = $data->get(self::COSE_KEY_PARAM_ALG);
        $modulus = $data->get(self::KTP_N);
        $exponent = $data->get(self::KTP_E);

        return new RsaKey($modulus, $exponent, $algorithm);
    }

    public function verifySignature(ByteBuffer $data, ByteBuffer $signature): bool
    {
        $verifier = new OpenSslVerifier($this->getAlgorithm());
        return $verifier->verify($data->getBinaryString(), $signature->getBinaryString(), $this->asPem());
    }

    /**
     * Removes all leading zero bytes from a ByteBuffer, but keeps one zero byte if it is the only byte left and the
     * original buffer did not have zero length.
     */
    private function compactIntegerBuffer(ByteBuffer $buffer): ByteBuffer
    {
        $length = $buffer->getLength();
        $raw = $buffer->getBinaryString();
        for ($i = 0; $i < ($length - 1); $i++) {
            if (ord($raw[$i]) !== 0) {
                break;
            }
        }
        if ($i !== 0) {
            return new ByteBuffer(\substr($raw, $i));
        }
        return $buffer;
    }

    public function getModulus(): ByteBuffer
    {
        return $this->modulus;
    }

    public function getExponent(): ByteBuffer
    {
        return $this->exponent;
    }

    public function asDer(): string
    {
        // DER encoded RSA key
        return
            Der::sequence(
                Der::sequence(
                    Der::oid("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01") . // OID 1.2.840.113549.1.1.1 rsaEncryption
                    Der::nullValue()
                ) .
                Der::bitString(
                    Der::sequence(
                        Der::unsignedInteger($this->modulus->getBinaryString()) .
                        Der::unsignedInteger($this->exponent->getBinaryString())
                    )
                )
            );
    }

    public function getCbor(): ByteBuffer
    {
        $map = [
            self::COSE_KEY_PARAM_KTY => self::COSE_KTY_RSA,
            self::COSE_KEY_PARAM_ALG => $this->getAlgorithm(),
            self::KTP_N => $this->modulus,
            self::KTP_E => $this->exponent,
        ];
        return new ByteBuffer(CborEncoder::encodeMap(CborMap::fromArray($map)));
    }

    protected function algorithmSupported(int $algorithm): bool
    {
        return in_array($algorithm, self::SUPPORTED_ALGORITHMS, true);
    }
}
