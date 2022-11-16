<?php

namespace MadWizard\WebAuthn\Credential;

use Exception;
use MadWizard\WebAuthn\Exception\NotAvailableException;
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
        if ($rawBytes === '') {
            // https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id
            throw new WebAuthnException('User handle must not be empty');
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

    public static function random(int $length = self::MAX_USER_HANDLE_BYTES): self
    {
        try {
            return new UserHandle(random_bytes($length));
        } catch (Exception $e) {
            throw new NotAvailableException('Cannot generate random bytes for user handle.', 0, $e);
        }
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->raw, $other->raw);
    }
}
