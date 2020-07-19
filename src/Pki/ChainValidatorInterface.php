<?php

namespace MadWizard\WebAuthn\Pki;

interface ChainValidatorInterface
{
    /**
     * @param X509Certificate ...$certificates
     */
    public function validateChain(X509Certificate ...$certificates): bool;
}
