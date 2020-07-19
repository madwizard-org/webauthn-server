<?php

namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;

interface TrustPathValidatorInterface
{
    public function validate(TrustPathInterface $trustPath, TrustAnchorInterface $trustAnchor): bool;
}
