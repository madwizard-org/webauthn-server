<?php

namespace MadWizard\WebAuthn\Format;

use ArrayAccess;
use ArrayObject;
use JsonSerializable;
use MadWizard\WebAuthn\Exception\CborException;

final class CborMap implements ArrayAccess, JsonSerializable
{
    /**
     * @var array[]
     * @phpstan-var array<string, array{0:mixed, 1:mixed}>
     */
    private $entries = [];

    public function __construct()
    {
    }

    private function getInternalKey($key): string
    {
        $keyType = gettype($key);
        if ($keyType !== 'string' && $keyType !== 'integer') {
            throw new CborException('Only string and integer values may be used as keys.');
        }
        return sprintf('%s:%s', $keyType, (string) $key);
    }

    public function set($key, $value): void
    {
        $this->entries[$this->getInternalKey($key)] = [$key, $value];
    }

    public function has($key): bool
    {
        $internalKey = $this->getInternalKey($key);
        return array_key_exists($internalKey, $this->entries);
    }

    public function get($key)
    {
        $internalKey = $this->getInternalKey($key);
        if (!array_key_exists($internalKey, $this->entries)) {
            throw new CborException("Key $internalKey is not present in CBOR map.");
        }
        return $this->entries[$internalKey][1];
    }

    public function remove($key)
    {
        $internalKey = $this->getInternalKey($key);
        if (!isset($this->entries[$internalKey])) {
            throw new CborException("Key $internalKey is not present in CBOR map.");
        }
        unset($this->entries[$internalKey]);
    }

    public function count(): int
    {
        return count($this->entries);
    }

    /**
     * @phpstan-return array<array{0:mixed, 1:mixed}>>
     */
    public function getEntries(): array
    {
        return array_values($this->entries);
    }

    public function getKeys(): array
    {
        return array_map(function ($item) { return $item[0]; }, array_values($this->entries));
    }

    public function copy(): self
    {
        return clone $this;
    }

    public static function fromArray(array $array): self
    {
        $map = new CborMap();
        foreach ($array as $k => $v) {
            $map->set($k, $v);
        }
        return $map;
    }

    public function offsetExists($offset)
    {
        return $this->has($offset);
    }

    public function offsetGet($offset)
    {
        return $this->get($offset);
    }

    public function offsetSet($offset, $value)
    {
        return $this->set($offset, $value);
    }

    public function offsetUnset($offset)
    {
        $this->remove($offset);
    }

    public function jsonSerialize()
    {
        $obj = new ArrayObject();
        foreach ($this->entries as [$k, $v]) {
            $obj[$k] = $v;
        }
        return $obj;
    }
}
