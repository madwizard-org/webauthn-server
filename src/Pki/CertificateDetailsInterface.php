<?php

namespace MadWizard\WebAuthn\Pki;

interface CertificateDetailsInterface
{
    public function verifySignature(string $data, string $signature, int $coseAlgorithm): bool;

    public function getCertificateVersion(): ?int;

    public function getOrganizationalUnit(): string;

    public function isCA(): ?bool;

    public function getSubjectAlternateNameDN(string $oid): string;

    public function extendedKeyUsageContains(string $oid): bool;

    public function getSubject(): string;

    public function getSubjectCommonName(): string;

    public function getPublicKeyDer(): string;

    public function getExtensionData(string $oid): ?CertificateExtension;

    /**
     * Returns public key identifier as hexadecimal string, using method 1 in RFC 5280.
     */
    public function getPublicKeyIdentifier(): string;
}
