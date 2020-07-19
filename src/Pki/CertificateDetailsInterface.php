<?php

namespace MadWizard\WebAuthn\Pki;

use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Format\ByteBuffer;

interface CertificateDetailsInterface
{
    public function verifySignature(string $data, string $signature, int $coseAlgorithm): bool;

    public function getFidoAaguidExtensionValue(): ?Aaguid;

    public function getCertificateVersion(): ?int;

    public function getOrganizationalUnit(): string;

    public function isCA(): ?bool;

    public function getSubjectAlternateNameDN(string $oid): string;

    public function extendedKeyUsageContains(string $oid): bool;

    public function getSubject(): string;

    public function getSubjectCommonName(): string;

    public function getPublicKeyDer(): string;

    public function getExtensionData(string $oid): ?ByteBuffer;

    /**
     * Returns public key identifier as hexadecimal string, using method 1 in RFC 5280.
     */
    public function getPublicKeyIdentifier(): string;
}
