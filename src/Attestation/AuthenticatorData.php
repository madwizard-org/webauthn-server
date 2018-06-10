<?php


namespace MadWizard\WebAuthn\Attestation;

use MadWizard\WebAuthn\Crypto\COSEKey;
use MadWizard\WebAuthn\Format\ByteBuffer;

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
            $aaguid = $data->getBytes($offset, self::LENGTH_AAGUID);
            $offset += self::LENGTH_AAGUID;
            $credentialIdLength = $data->getUint16Val($offset);
            $offset += 2;
            $this->credentialId = new ByteBuffer($data->getBytes($offset, $credentialIdLength));
            $offset += $credentialIdLength;
            $this->key = COSEKey::parseCBOR($data, $offset, $endOffset);
            $offset = $endOffset;
        }

        if ($this->hasExtensionData()) {
            // TODO
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
        return ($this->flags & self::FLAG_UP);
    }

    public function isUserVerified(): bool
    {
        return ($this->flags & self::FLAG_UV);
    }

    public function hasAttestedCredentialData(): bool
    {
        return ($this->flags & self::FLAG_AT);
    }

    public function hasExtensionData(): bool
    {
        return ($this->flags & self::FLAG_ED);
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
