<?php

namespace MadWizard\WebAuthn\Credential;

use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\BinaryHandle;
use MadWizard\WebAuthn\Format\ByteBuffer;
use function hash_equals;

class CredentialId extends BinaryHandle
{
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
