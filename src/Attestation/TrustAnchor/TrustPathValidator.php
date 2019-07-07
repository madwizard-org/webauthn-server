<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Pki\CertificateParserInterface;
use function array_merge;
use function array_reverse;

class TrustPathValidator implements TrustPathValidatorInterface
{
    /**
     * @var CertificateParserInterface
     */
    private $parser;

    public function __construct(CertificateParserInterface $parser)
    {
        $this->parser = $parser;
    }

    /**
     * @param CertificateTrustPath $trustPath
     * @param string[] $anchorCertificates
     * @return bool
     */
    public function validateCertificateChain(CertificateTrustPath $trustPath, array $anchorCertificates) : bool
    {
        foreach ($anchorCertificates as $rootCertificate) {
            $list = array_merge([$rootCertificate], array_reverse($trustPath->getCertificates()));
            if ($this->parser->validateChain($list)) {
                return true;
            }
        }
        return false;
    }
}
