<?php

namespace MadWizard\WebAuthn\Format;

/**
 * Trait to map Serializable methods serialize and unserialize to PHP 7.4+ __serialize and __unserialize
 * to maintain backwards compatibility. Subclasses should override __(un)serialize, not (un)serialize.
 */
trait SerializableTrait
{
    abstract public function __serialize(): array;

    abstract public function __unserialize(array $data): void;

    /**
     * @final
     */
    public function serialize(): string
    {
        return \serialize($this->__serialize());
    }

    /**
     * @final
     *
     * @param string $serialized
     */
    public function unserialize($serialized): void
    {
        $this->__unserialize(\unserialize($serialized));
    }
}
