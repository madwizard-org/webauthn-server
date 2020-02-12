<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Pki\ChainValidatorInterface;
use MadWizard\WebAuthn\Pki\X509Certificate;
use function array_merge;
use function array_reverse;

class TrustPathValidator implements TrustPathValidatorInterface
{
    /**
     * @var ChainValidatorInterface
     */
    private $chainValidator;

    public function __construct(ChainValidatorInterface $chainValidator)
    {
        $this->chainValidator = $chainValidator;
    }

    /**
     * @param CertificateTrustPath $trustPath
     * @param X509Certificate[] $anchorCertificates
     * @return bool
     */
    public function validateCertificateChain(CertificateTrustPath $trustPath, array $anchorCertificates) : bool
    {
        foreach ($anchorCertificates as $rootCertificate) {
            $list = array_merge([$rootCertificate], array_reverse($trustPath->getCertificates()));
            if ($this->chainValidator->validateChain($list)) {
                return true;
            }
        }
        return false;
    }
}
