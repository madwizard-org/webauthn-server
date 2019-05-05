<?php



namespace MadWizard\WebAuthn\Pki;

interface CertificateParserInterface
{
    public function parsePem(string $pem) : CertificateDetailsInterface;

    /**
     * @param string[] $pems Certificates ordered from trust anchor to target
     * @return bool
     */
    public function validateChain(array $pems) : bool;
}
