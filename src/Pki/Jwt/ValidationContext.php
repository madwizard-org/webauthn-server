<?php


namespace MadWizard\WebAuthn\Pki\Jwt;

use MadWizard\WebAuthn\Crypto\CoseKeyInterface;

final class ValidationContext
{
    /**
     * @var string[]
     */
    private $allowedAlgorithms;

    /**
     * @var CoseKeyInterface
     */
    private $key;

    /**
     * @param string[] $allowedAlgorithms
     */
    public function __construct(array $allowedAlgorithms, CoseKeyInterface $key)
    {
        $this->key = $key;
        // TODO: check types
        $this->allowedAlgorithms = $allowedAlgorithms;
    }

    public function getAllowedAlgorithms(): array
    {
        return $this->allowedAlgorithms;
    }

    public function getKey(): CoseKeyInterface
    {
        return $this->key;
    }
}
