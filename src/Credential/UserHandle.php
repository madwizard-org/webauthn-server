<?php

namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\BinaryHandle;
use MadWizard\WebAuthn\Format\ByteBuffer;
use function hash_equals;
use function sprintf;

class UserHandle extends BinaryHandle
{
    /**
     * SPEC: 4 Terminology - User Handle.
     */
    public const MAX_USER_HANDLE_BYTES = 64;

    protected function __construct(string $rawBytes)
    {
        if (\strlen($rawBytes) > self::MAX_USER_HANDLE_BYTES) {
            throw new WebAuthnException(sprintf('User handle cannot be larger than %d bytes.', self::MAX_USER_HANDLE_BYTES));
        }
        parent::__construct($rawBytes);
    }

    public static function fromString(string $base64urlString): self
    {
        return new self(Base64UrlEncoding::decode($base64urlString));
    }

    public static function fromBinary(string $binary): self
    {
        return new self($binary);
    }

    public static function fromHex(string $hex): self
    {
        return new self(parent::convertHex($hex));
    }

    public static function fromBuffer(ByteBuffer $buffer): self
    {
        return new self($buffer->getBinaryString());
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->raw, $other->raw);
    }
}
