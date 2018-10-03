<?php


namespace MadWizard\WebAuthn\Attestation\Tpm;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;

class TpmAttest extends AbstractTpmStructure
{
    private const TPM_GENERATED = "\xFF\x54\x43\x47";

    public const TPM_ST_ATTEST_CERTIFY = 0x8017;

    /**
     * @var ByteBuffer
     */
    private $attName;

    public function __construct(ByteBuffer $data)
    {
        // Read magic
        $magic = $data->getBytes(0, 4);
        if ($magic !== self::TPM_GENERATED) {
            throw new ParseException('Magic bytes of TPM attestation are not TPM_GENERATED sequence.');
        }

        // Read type
        $type = $data->getUint16Val(4);
        if ($type !== self::TPM_ST_ATTEST_CERTIFY) {
            throw new ParseException(sprintf('Wrong type for TPMS_ATTEST structure, expecting TPM_ST_ATTEST_CERTIFY, not 0x%04Xd.', $type));
        }
        //$this->objectAttributes = $data->getUint32Val(6);

        $offset = 6;

        // qualifiedSigner
        $this->readLengthPrefixed($data, $offset);

        // Extra data
        $this->readLengthPrefixed($data, $offset);

        // Clock info
        $this->readFixed($data, $offset, 17);

        // Firmware version
        $this->readFixed($data, $offset, 8);

        // Attested name
        $this->attName = $this->readLengthPrefixed($data, $offset);

        // Attested qualified name
        $this->readLengthPrefixed($data, $offset);

        if ($offset !== $data->getLength()) {
            throw new ParseException('Unexpected bytes after TPMS_ATTEST structure.');
        }
    }

    /**
     * @return ByteBuffer
     */
    public function getAttName(): ByteBuffer
    {
        return $this->attName;
    }
}
