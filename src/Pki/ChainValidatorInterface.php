<?php

namespace MadWizard\WebAuthn\Pki;

interface ChainValidatorInterface
{
    /**
     * @param X509Certificate ...$certificates From root to end certificate
     */
    public function validateChain(X509Certificate ...$certificates): bool;
}
