<?php


namespace MadWizard\WebAuthn\Attestation\TrustPath;

class CertificateTrustPath implements TrustPathInterface
{
    /**
     * @var array
     */
    private $certificates;

    public function __construct(array $certificates)
    {
        $this->certificates = $certificates;
    }

    /**
     * @return string[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }
}
