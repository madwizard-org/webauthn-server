<?php

namespace MadWizard\WebAuthn\Attestation\Identifier;

use MadWizard\WebAuthn\Exception\ParseException;

class Aaid implements IdentifierInterface
{
    public const TYPE = 'aaid';

    /**
     * @var string
     */
    private $aaid;

    public function __construct(string $aaid)
    {
        $aaid = strtolower($aaid);
        if (!preg_match('~^[0-9A-Fa-f]{4}#[0-9A-Fa-f]{4}$~', $aaid)) {
            throw new ParseException('Invalid AAID');
        }
        $this->aaid = $aaid;
    }

    public function getType(): string
    {
        return self::TYPE;
    }

    public function toString(): string
    {
        return $this->aaid;
    }

    public function equals(IdentifierInterface $identifier): bool
    {
        return $identifier instanceof self && $this->aaid === $identifier->aaid;
    }
}
