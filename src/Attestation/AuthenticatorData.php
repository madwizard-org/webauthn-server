<?php


namespace MadWizard\WebAuthn\Attestation;

use MadWizard\WebAuthn\Crypto\COSEKey;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CBORDecoder;

class AuthenticatorData
{
    /**
     * User present (UP)
     */
    private const FLAG_UP = 1 << 0;

    /**
     * User verified (UV)
     */
    private const FLAG_UV = 1 << 2;

    /**
     * Attestated credential data included (AT)
     */
    private const FLAG_AT = 1 << 6;

    /**
     * Extension data included (AT)
     */
    private const FLAG_ED = 1 << 7;

    /**
     * SHA-256 hash of the RP ID associated with the credential.
     * @var ByteBuffer
     */
    private $rpIdHash;

    /**
     * @var int FLAG_* flags
     */
    private $flags;

    /**
     * @var int
     */
    private $signCount;

    /**
     * @var COSEKey|null
     */
    private $key;

    /**
     * @var ByteBuffer|null
     */
    private $credentialId;

    /**
     * @var ByteBuffer|null
     */
    private $aaguid;

    private const LENGTH_RP_ID_HASH = 32;

    private const LENGTH_AAGUID = 16;

    public function __construct(ByteBuffer $data)
    {
        $offset = 0;
        $this->rpIdHash = new ByteBuffer($data->getBytes(0, self::LENGTH_RP_ID_HASH));
        $offset += self::LENGTH_RP_ID_HASH;

        $this->flags = $data->getByteVal($offset);
        $offset++;
        $this->signCount = $data->getUint32Val($offset);
        $offset += 4;

        if ($this->hasAttestedCredentialData()) {
            $this->aaguid = new ByteBuffer($data->getBytes($offset, self::LENGTH_AAGUID));
            $offset += self::LENGTH_AAGUID;
            $credentialIdLength = $data->getUint16Val($offset);
            $offset += 2;
            $this->credentialId = new ByteBuffer($data->getBytes($offset, $credentialIdLength));
            $offset += $credentialIdLength;
            $this->key = COSEKey::parseCBOR($data, $offset, $endOffset);
            $offset = $endOffset;
        }

        if ($this->hasExtensionData()) {
            $extensionData = CBORDecoder::decodeInPlace($data, $offset, $endOffset);
            $offset = $endOffset;
            if (!is_array($extensionData)) {
                throw new ParseException('Expected CBOR map for extension data in authenticator data.');
            }
        }
        if ($offset !== $data->getLength()) {
            throw new ParseException('Unexpected bytes at end of AuthenticatorData.');
        }
    }

    public function getRpIdHash() : ByteBuffer
    {
        return $this->rpIdHash;
    }

    public function getSignCount() : int
    {
        return $this->signCount;
    }

    public function isUserPresent(): bool
    {
        return ($this->flags & self::FLAG_UP) !== 0;
    }

    public function isUserVerified(): bool
    {
        return ($this->flags & self::FLAG_UV) !== 0;
    }

    public function hasAttestedCredentialData(): bool
    {
        return ($this->flags & self::FLAG_AT) !== 0;
    }

    public function hasExtensionData(): bool
    {
        return ($this->flags & self::FLAG_ED) !== 0;
    }

    public function getCredentialId(): ?ByteBuffer
    {
        return $this->credentialId;
    }

    /**
     * @return COSEKey|null
     */
    public function getKey(): ?COSEKey
    {
        return $this->key;
    }
}
