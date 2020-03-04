<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;

interface TrustPathValidatorInterface
{
    /**
     * @param TrustPathInterface $trustPath
     * @param TrustAnchorInterface $trustAnchor
     * @return bool
     */
    public function validate(TrustPathInterface $trustPath, TrustAnchorInterface $trustAnchor) : bool;
}
