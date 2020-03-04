<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
use MadWizard\WebAuthn\Pki\ChainValidatorInterface;
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
     * @param TrustPathInterface $trustPath
     * @param TrustAnchorInterface $trustAnchor
     * @return bool
     */
    public function validate(TrustPathInterface $trustPath, TrustAnchorInterface $trustAnchor) : bool
    {
        if ($trustAnchor instanceof CertificateTrustAnchor && $trustPath instanceof CertificateTrustPath) {
            if ($this->chainValidator->validateChain($trustAnchor->getCertificate(), ...array_reverse($trustPath->getCertificates()))) {
                return true;
            }
        }
        return false;
    }
}
