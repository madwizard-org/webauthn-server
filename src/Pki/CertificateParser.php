<?php



namespace MadWizard\WebAuthn\Pki;

class CertificateParser implements CertificateParserInterface
{
    public function parsePem(string $pem): CertificateDetailsInterface
    {
        return CertificateDetails::fromPem($pem);
    }
}
