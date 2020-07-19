<?php

namespace MadWizard\WebAuthn\Pki;

interface CertificateParserInterface
{
    public function parsePem(string $pem): CertificateDetailsInterface;
}
