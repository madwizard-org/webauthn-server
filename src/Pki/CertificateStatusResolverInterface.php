<?php

namespace MadWizard\WebAuthn\Pki;

interface CertificateStatusResolverInterface
{
    public function isRevoked(X509Certificate $subject, X509Certificate $issuer): bool;
}
