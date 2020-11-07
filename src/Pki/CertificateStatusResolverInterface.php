<?php

namespace MadWizard\WebAuthn\Pki;

interface CertificateStatusResolverInterface
{
    /**
     * @param X509Certificate $subject           Certificate to be checked for revocation
     * @param X509Certificate ...$caCertificates List of trusted CA certificates
     *
     * @return bool True if the certificate is revoked, false otherwise
     */
    public function isRevoked(X509Certificate $subject, X509Certificate ...$caCertificates): bool;
}
