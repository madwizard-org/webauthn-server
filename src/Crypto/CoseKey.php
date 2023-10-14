<?php

namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborDecoder;
use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Format\DataValidator;

abstract class CoseKey implements CoseKeyInterface
{
    /**
     * OKP key type.
     */
    protected const COSE_KTY_OKP = 1;

    /**
     * EC2 key type.
     */
    protected const COSE_KTY_EC2 = 2;

    /**
     * RSA key type.
     */
    protected const COSE_KTY_RSA = 3;

    /**
     * @var int
     */
    private $algorithm;

    /**
     * Identification of the key type.
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     */
    protected const COSE_KEY_PARAM_KTY = 1;

    /**
     * Key identification value.
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     */
    protected const COSE_KEY_PARAM_KID = 2;

    /**
     * Key usage restriction to this algorithm.
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     */
    protected const COSE_KEY_PARAM_ALG = 3;

    /**
     * CoseKey constructor.
     *
     * @param int $algorithm IANA COSE Algorithm
     *
     * @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     */
    public function __construct(int $algorithm)
    {
        if (!$this->algorithmSupported($algorithm)) {
            throw new WebAuthnException('Algorithm not supported');
        }
        $this->algorithm = $algorithm;
    }

    public function toString(): string
    {
        return $this->getCbor()->getBase64Url();
    }

    public static function parseCbor(ByteBuffer $buffer, int $offset = 0, int &$endOffset = null): CoseKey
    {
        // Fix incorrect EdDSA keys
        $isIncorrectKey = $buffer->getBytes($offset, 17) == "\xa3\x01\x63\x4f\x4b\x50\x03\x27\x20\x67\x45\x64\x32\x35\x35\x31\x39";
        if ($isIncorrectKey) {
            $buffer = new ByteBuffer($buffer->getBytes(0, $offset) . "\xa4" . $buffer->getBytes($offset + 1, $buffer->getLength() - $offset - 1));
        }
        $data = CborDecoder::decodeInPlace($buffer, $offset, $endOffset);

        if (!$data instanceof CborMap) {
            throw new DataValidationException('Failed to decode CBOR encoded COSE key'); // TODO: change exceptions
        }

        // Replace textual kty's with their numeric counterparts
        if ($data->get(self::COSE_KEY_PARAM_KTY) === 'OKP')
            $data->set(self::COSE_KEY_PARAM_KTY, 1);
        elseif ($data->get(self::COSE_KEY_PARAM_KTY) === 'EC2')
            $data->set(self::COSE_KEY_PARAM_KTY, 2);

        DataValidator::checkMap(
            $data,
            [
                self::COSE_KEY_PARAM_KTY => 'integer',
            ],
            false
        );

        // Fix incorrect EdDSA keys, part 2: x coordinate should be bstr, not array
        if ($isIncorrectKey && $data->has(-2) && is_array($data->get(-2))) {
            $data->set(-2, new ByteBuffer(implode(array_map('chr', $data->get(-2)))));
        }

        $keyType = $data->get(self::COSE_KEY_PARAM_KTY);
        return self::createKey($keyType, $data);
    }

    public static function fromString(string $key): CoseKey
    {
        return self::parseCbor(ByteBuffer::fromBase64Url($key));
    }

    private static function createKey(int $keyType, CborMap $data): CoseKey
    {
        if ($keyType === self::COSE_KTY_EC2) {
            return Ec2Key::fromCborData($data);
        }
        if ($keyType === self::COSE_KTY_OKP) {
            return OkpKey::fromCborData($data);
        }
        if ($keyType === self::COSE_KTY_RSA) {
            return RsaKey::fromCborData($data);
        }
        throw new WebAuthnException(sprintf('Key type %d not supported', $keyType));
    }

    abstract public function getCbor(): ByteBuffer;

    public function getAlgorithm(): int
    {
        return $this->algorithm;
    }

    abstract public function verifySignature(ByteBuffer $data, ByteBuffer $signature): bool;

    abstract protected function algorithmSupported(int $algorithm): bool;

    abstract public function asDer(): string;

    public function asPem(): string
    {
        return Der::pem('PUBLIC KEY', $this->asDer());
    }
}
