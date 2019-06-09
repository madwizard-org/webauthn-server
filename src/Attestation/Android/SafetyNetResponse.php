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

    /**
     * @var int|float
     */
    private $timestampMs;

    public function __construct(string $nonce, array $x5c, bool $ctsProfileMatch, $timestampMs)
    {
        $this->nonce = $nonce;
        $this->x5c = $x5c;
        $this->ctsProfileMatch = $ctsProfileMatch;
        $this->timestampMs = $timestampMs;
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

    public function getTimestampMs()
    {
        return $this->timestampMs;
    }
}
