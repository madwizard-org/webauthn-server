<?php


namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Dom\COSEAlgorithm;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;

class RSAKey extends COSEKey
{
    /**
     * RSA modulus n key type parameter (key type 3, RSA)
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    private const KTP_N = -1;

    /**
     * RSA exponent e key type parameter (key type 3, RSA)
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    private const KTP_E = -2;

    /**
     * RSA modulus. Unsigned integer value represented as binary buffer with leading zero bytes removed
     * @var ByteBuffer
     */
    private $modulus;

    /**
     * RSA exponent. Unsigned integer value represented as binary buffer with leading zero bytes removed
     * @var ByteBuffer
     */
    private $exponent;

    public function __construct(ByteBuffer $modulus, ByteBuffer $exponent, int $algorithm)
    {
        parent::__construct($algorithm);
        $this->modulus = $this->compactIntegerBuffer($modulus);
        $this->exponent = $this->compactIntegerBuffer($exponent);
    }

    public static function fromCBORData(array $data) : RSAKey
    {
        DataValidator::checkTypes(
            $data,
            [
                self::COSE_KEY_PARAM_KTY => 'integer',
                self::COSE_KEY_PARAM_ALG => 'integer',
                self::KTP_N => ByteBuffer::class,
                self::KTP_E => ByteBuffer::class,
            ]
        );


        $alorithm = $data[self::COSE_KEY_PARAM_ALG];
        $modulus = $data[self::KTP_N];
        $exponent = $data[self::KTP_E];

        return new RSAKey($modulus, $exponent, $alorithm);
    }

    public function verifySignature(ByteBuffer $data, ByteBuffer $signature): bool
    {
        $publicKey = openssl_pkey_get_public($this->asPEM());
        if ($publicKey === false) {
            throw new WebAuthnException('Public key invalid');
        }
        try {
            if ($this->getAlgorithm() === COSEAlgorithm::RS256) {
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
        } finally {
            openssl_free_key($publicKey);
        }
    }

    /**
     * Removes all leading zero bytes from a ByteBuffer, but keeps one zero byte if it is the only byte left and the
     * original buffer did not have zero length.
     *
     * @param ByteBuffer $buffer
     * @return ByteBuffer
     */
    private function compactIntegerBuffer(ByteBuffer $buffer)
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

    /**
     * @return ByteBuffer
     */
    public function getModulus(): ByteBuffer
    {
        return $this->modulus;
    }

    /**
     * @return ByteBuffer
     */
    public function getExponent(): ByteBuffer
    {
        return $this->exponent;
    }

    public function asPEM() : string
    {
        // DER encoded RSA key
        $der =
            DER::sequence(
                DER::sequence(
                    DER::oid("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01") . // OID 1.2.840.113549.1.1.1 rsaEncryption
                    DER::nullValue()
                ) .
                DER::bitString(
                    DER::sequence(
                        DER::unsignedInteger($this->modulus->getBinaryString()) .
                        DER::unsignedInteger($this->exponent->getBinaryString())
                    )
                )
            );

        return DER::pem('PUBLIC KEY', $der);
    }

    protected function algorithmSupported(int $algorithm) : bool
    {
        return ($algorithm === COSEAlgorithm::RS256);
    }
}
