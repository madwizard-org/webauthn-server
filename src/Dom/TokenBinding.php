<?php

namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\NotAvailableException;
use MadWizard\WebAuthn\Exception\UnexpectedValueException;
use MadWizard\WebAuthn\Format\ByteBuffer;

final class TokenBinding
{
    /**
     * @var string
     */
    private $status;

    /**
     * @var ByteBuffer|null
     */
    private $id;

    public function __construct(string $status, ?ByteBuffer $id)
    {
        if (!TokenBindingStatus::isValidValue($status)) {
            throw new UnexpectedValueException(sprintf('Invalid token binding status "%s".', $status));
        }

        $this->status = $status;
        if ($this->status === TokenBindingStatus::PRESENT && $id === null) {
            throw new UnexpectedValueException("Token binding id should be set if status is 'present'.");
        }
        if ($this->status === TokenBindingStatus::SUPPORTED && $id !== null) {
            throw new UnexpectedValueException("Token binding id cannot be set if status is 'supported'.");
        }
        $this->id = $id;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * @return ByteBuffer Returns the token binding ID
     *
     * @throws NotAvailableException
     */
    public function getId(): ByteBuffer
    {
        if ($this->id === null) {
            throw new NotAvailableException('No token binding ID available.');
        }
        return $this->id;
    }

    public function hasId(): bool
    {
        return $this->id !== null;
    }
}
