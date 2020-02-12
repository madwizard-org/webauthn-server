<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;

interface TrustPathValidatorInterface
{
    /**
     * @param CertificateTrustPath $trustPath
     * @param string[] $anchorCertificates
     * @return bool
     */
    public function validateCertificateChain(CertificateTrustPath $trustPath, array $anchorCertificates):bool; // TODO generic trustpath?
}
