<?php

namespace MadWizard\WebAuthn\Pki\Jwt;

use MadWizard\WebAuthn\Crypto\CoseKeyInterface;

final class ValidationContext
{
    public const DEFAULT_CLOCK_LEEWAY = 1 * 60;

    /**
     * @var string[]
     */
    private $allowedAlgorithms;

    /**
     * @var CoseKeyInterface
     */
    private $key;

    /**
     * @var int|null
     */
    private $referenceUnixTime;

    /**
     * @param string[] $allowedAlgorithms
     */
    public function __construct(array $allowedAlgorithms, CoseKeyInterface $key)
    {
        $this->key = $key;
        // TODO: check types
        $this->allowedAlgorithms = $allowedAlgorithms;
    }

    /**
     * @return string[]
     */
    public function getAllowedAlgorithms(): array
    {
        return $this->allowedAlgorithms;
    }

    public function getKey(): CoseKeyInterface
    {
        return $this->key;
    }

    public function getReferenceUnixTime(): int
    {
        return $this->referenceUnixTime ?? time();
    }

    public function getClockLeeway(): int
    {
        return self::DEFAULT_CLOCK_LEEWAY;
    }

    public function withReferenceUnixTime(int $timestamp): self
    {
        $copy = clone $this;
        $copy->referenceUnixTime = $timestamp;
        return $copy;
    }
}
