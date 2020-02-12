<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Pki\X509Certificate;

interface TrustPathValidatorInterface
{
    /**
     * @param CertificateTrustPath $trustPath
     * @param X509Certificate[] $anchorCertificates
     * @return bool
     */
    public function validateCertificateChain(CertificateTrustPath $trustPath, array $anchorCertificates):bool; // TODO generic trustpath?
}
