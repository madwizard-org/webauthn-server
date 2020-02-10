<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

class CertificateTrustAnchor implements TrustAnchorInterface
{
    public const TYPE = 'certificate';

    /**
     * @var string
     */
    private $pem;

    public function __construct(string $pem)
    {
        $this->pem = $pem;
    }

    public function getPem() :string
    {
        return $this->pem;
    }

    public function getType(): string
    {
        return self::TYPE;
    }
}
