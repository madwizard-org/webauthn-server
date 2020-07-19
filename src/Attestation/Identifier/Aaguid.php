<?php

namespace MadWizard\WebAuthn\Attestation\Identifier;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;

class Aaguid implements IdentifierInterface
{
    public const TYPE = 'aaguid';

    public const AAGUID_LENGTH = 16;

    /**
     * @var ByteBuffer
     */
    private $raw;

    public function __construct(ByteBuffer $raw)
    {
        if ($raw->getLength() !== self::AAGUID_LENGTH) {
            throw new ParseException(sprintf('AAGUID should be %d bytes, not %d', self::AAGUID_LENGTH, $raw->getLength()));
        }
        $this->raw = $raw;
    }

    public function getType(): string
    {
        return self::TYPE;
    }

    public static function parseString(string $aaguid)
    {
        if (!preg_match('~^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$~', $aaguid)) {
            throw new ParseException('Invalid AAGUID');
        }
        $hex = substr($aaguid, 0, 8) .
            substr($aaguid, 9, 4) .
            substr($aaguid, 14, 4) .
            substr($aaguid, 19, 4) .
            substr($aaguid, 24, 12);

        return new Aaguid(ByteBuffer::fromHex($hex));
    }

    public function toString(): string
    {
        $hex = $this->raw->getHex();
        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12)
        );
    }

    public function getHex(): string
    {
        return $this->raw->getHex();
    }

    public function isZeroAaguid(): bool
    {
        // Check if all zero bytes - U2F authenticators use this to indicate they have no AAGUID
        return strspn($this->raw->getBinaryString(), "\0") === self::AAGUID_LENGTH;
    }

    public function equals(IdentifierInterface $identifier): bool
    {
        return $identifier instanceof self && $this->raw->equals($identifier->raw);
    }
}
