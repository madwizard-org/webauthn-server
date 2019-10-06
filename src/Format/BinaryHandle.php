<?php


namespace MadWizard\WebAuthn\Format;

use InvalidArgumentException;
use Serializable;
use function bin2hex;
use function hex2bin;

abstract class BinaryHandle implements Serializable
{
    use SerializableTrait;

    /**
     * @var string
     */
    protected $raw;

    protected function __construct(string $rawBytes)
    {
        $this->raw = $rawBytes;
    }

    public function toString(): string
    {
        return Base64UrlEncoding::encode($this->raw);
    }

    public function toBinary(): string
    {
        return $this->raw;
    }

    public function toHex(): string
    {
        return bin2hex($this->raw);
    }

    public function toBuffer() : ByteBuffer
    {
        return new ByteBuffer($this->raw);
    }

    protected static function convertHex(string $hex) : string
    {
        $bin = @hex2bin($hex);
        if ($bin === false) {
            throw new InvalidArgumentException('Invalid hex string');
        }
        return $bin;
    }

    public function __serialize(): array
    {
        return [
            'raw' => $this->raw,
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->raw = $data['raw'];
    }
}
