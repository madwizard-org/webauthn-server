<?php


namespace MadWizard\WebAuthn\Pki;

interface ChainValidatorInterface
{
    /**
     * @param X509Certificate ...$certificates
     * @return bool
     */
    public function validateChain(X509Certificate... $certificates) : bool;
}
