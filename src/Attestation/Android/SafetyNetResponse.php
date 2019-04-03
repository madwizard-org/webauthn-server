<?php


namespace MadWizard\WebAuthn\Attestation\Android;

class SafetyNetResponse implements SafetyNetResponseInterface
{
    /**
     * @var string
     */
    private $nonce;

    /**
     * @var array
     */
    private $x5c;

    /**
     * @var bool
     */
    private $ctsProfileMatch;

    public function __construct(string $nonce, array $x5c, bool $ctsProfileMatch)
    {
        $this->nonce = $nonce;
        $this->x5c = $x5c;
        $this->ctsProfileMatch = $ctsProfileMatch;
    }

    /**
     * @return string
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * @return string[]
     */
    public function getCertificateChain(): array
    {
        return $this->x5c;
    }

    /**
     * @return bool
     */
    public function isCtsProfileMatch(): bool
    {
        return $this->ctsProfileMatch;
    }
}
