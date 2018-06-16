<?php


namespace MadWizard\WebAuthn\Crypto;

use Exception;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CBOR;
use function array_key_exists;
use function is_array;
use function is_int;

abstract class COSEKey
{
    /**
     * EC2 key type
     */
    private const COSE_KTY_EC2 = 2;

    /**
     * RSA key type
     */
    private const COSE_KTY_RSA = 3;

    /**
     * @var int
     */
    private $algorithm;

    /**
     * Identification of the key type
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     */
    protected const COSE_KEY_PARAM_KTY = 1;

    /**
     * Key identification value
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     */
    private const COSE_KEY_PARAM_KID = 2;

    /**
     * Key usage restriction to this algorithm
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     */
    protected const COSE_KEY_PARAM_ALG = 3;

    /**
     * COSEKey constructor.
     * @param int $algorithm IANA COSE Algorithm
     * @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     */
    public function __construct(int $algorithm)
    {
        if (!$this->algorithmSupported($algorithm)) {
            throw new WebAuthnException('Algorithm not supported');
        }
        $this->algorithm = $algorithm;
    }

    public static function parseCBOR(ByteBuffer $buffer, int $offset = 0, int &$endOffset = null) : COSEKey
    {
        $data = CBOR::decodeInPlace($buffer, $offset, $endOffset);

        if (!is_array($data)) {
            throw new Exception('Failed to decode CBOR encoded COSE key'); // TODO: change exceptions
        }

        if (!array_key_exists(self::COSE_KEY_PARAM_KTY, $data)) {
            throw new Exception('Missing key type.');
        }

        $keyType = $data[self::COSE_KEY_PARAM_KTY];
        if (!is_int($keyType)) {
            throw new Exception('Wrong data type for key type');
        }

        return self::createKey($keyType, $data);
    }

    private static function createKey(int $keyType, array $data) : COSEKey
    {
        if ($keyType === self::COSE_KTY_EC2) {
            return EC2Key::fromCBORData($data);
        }
        if ($keyType === self::COSE_KTY_RSA) {
            return RSAKey::fromCBORData($data);
        }
        throw new Exception(sprintf('Key type %d not supported', $keyType));
    }

    /**
     * @return int
     */
    public function getAlgorithm(): int
    {
        return $this->algorithm;
    }

    abstract public function verifySignature(ByteBuffer $data, ByteBuffer $signature) : bool;

    abstract protected function algorithmSupported(int $algorithm) : bool;
}
