<?php


namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Format\ByteBuffer;

/**
 * Represents TPMT_PUBLIC structure
 */
class TpmPublic extends AbstractTpmStructure
{
    public const TPM_ALG_RSA = 0x0001;

    public const TPM_ALG_ECC = 0x0023;

    public const TPM_ALG_NULL = 0x0010;

    public const TPM_ALG_SHA = 0x0004; // ISO/IEC 10118-3 the SHA1 algorithm

    public const TPM_ALG_SHA1 = 0x0004; // ISO/IEC 10118-3 redefinition for documentation consistency TPM

    public const TPM_ALG_SHA256 = 0x000B; // ISO/IEC 10118-3 the SHA 256 algorithm

    public const TPM_ALG_SHA384 = 0x000C; //  ISO/IEC 10118-3 the SHA 384 algorithm

    public const TPM_ALG_SHA512 = 0x000D; // ISO/IEC 10118-3 the SHA 512 algorithm

    private const PHP_HASH_ALG_MAP = [
        self::TPM_ALG_SHA1 => 'sha1',
        self::TPM_ALG_SHA256 => 'sha256',
        self::TPM_ALG_SHA384 => 'sha384',
        self::TPM_ALG_SHA512 => 'sha512',
    ];

    /**
     * @var int
     */
    private $type;

    /**
     * @var int
     */
    private $objectAttributes;

    /**
     * @var int
     */
    private $nameAlg;

    /**
     * @var string
     */
    private $rawData;

    /**
     * @var KeyParametersInterface
     */
    private $parameters;

    /**
     * @var ByteBuffer
     */
    private $unique;

    public function __construct(ByteBuffer $data)
    {
        $this->rawData = $data->getBinaryString();
        $this->type = $data->getUint16Val(0);

        $this->nameAlg = $data->getUint16Val(2);
        $this->objectAttributes = $data->getUint32Val(4);

        $offset = 8;

        // TODO: check key bits with actual key length

        // Auth policy
        $this->readLengthPrefixed($data, $offset);

        $this->parameters = $this->parseParameters($this->type, $data, $offset);

        $this->unique = $this->readLengthPrefixed($data, $offset);

        if ($offset !== $data->getLength()) {
            throw new ParseException('Unexpected bytes after TPMT_PUBLIC structure.');
        }
    }

    private function parseParameters(int $type, ByteBuffer $buffer, int &$offset) : KeyParametersInterface
    {
        if ($type === self::TPM_ALG_RSA) {
            $parameters = TpmRsaParameters::parse($buffer, $offset, $endOffset);
            $offset = $endOffset;
            return $parameters;
        }
        if ($type === self::TPM_ALG_ECC) {
            $parameters = TpmEccParameters::parse($buffer, $offset, $endOffset);
            $offset = $endOffset;
            return $parameters;
        }
        throw new UnsupportedException(sprintf('TPM public key type %d is not supported.', $type));
    }

    /**
     * @return int
     */
    public function getType(): int
    {
        return $this->type;
    }

    /**
     * @return int
     */
    public function getObjectAttributes(): int
    {
        return $this->objectAttributes;
    }

    /**
     * @return KeyParametersInterface
     */
    public function getParameters(): KeyParametersInterface
    {
        return $this->parameters;
    }

    /**
     * @return int
     */
    public function getNameAlg(): int
    {
        return $this->nameAlg;
    }

    /**
     * @return ByteBuffer
     */
    public function getUnique(): ByteBuffer
    {
        return $this->unique;
    }

    public function generatePubInfoHash() : ByteBuffer
    {
        // pubInfoHash is the concatenation of nameAlg (16-bit uint) and a hash of this whole structure.

        $algo = self::PHP_HASH_ALG_MAP[$this->nameAlg] ?? null;
        if ($algo === null) {
            throw new UnsupportedException(sprintf('TPMT_PUBLIC nameAlg 0x%04X not supported for hashing.', $this->nameAlg));
        }

        return new ByteBuffer(pack('n', $this->nameAlg) . hash($algo, $this->rawData, true));
    }
}
