<?php

namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Pki\X509Certificate;

final class CertificateTrustAnchor implements TrustAnchorInterface
{
    public const TYPE = 'certificate';

    /**
     * @var X509Certificate
     */
    private $cert;

    public function __construct(X509Certificate $cert)
    {
        $this->cert = $cert;
    }

    public function getCertificate(): X509Certificate
    {
        return $this->cert;
    }

    public function getType(): string
    {
        return self::TYPE;
    }
}
