<?php


namespace MadWizard\WebAuthn\Pki;

interface ChainValidatorInterface
{
    /**
     * @param X509Certificate ...$certificatess
     * @return bool
     */
    public function validateChain(X509Certificate... $certificatess) : bool;
}
