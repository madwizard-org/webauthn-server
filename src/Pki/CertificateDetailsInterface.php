<?php

namespace MadWizard\WebAuthn\Pki;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface CertificateDetailsInterface
{
    public function verifySignature(string $data, string $signature, int $coseAlgorithm): bool;

    public function getFidoAaguidExtensionValue(): ?ByteBuffer;

    public function getCertificateVersion(): ?int;

    public function getOrganizationalUnit(): string;

    public function isCA(): ?bool;

    public function getSubjectAlternateNameDN(string $oid) : string;

    public function extendedKeyUsageContains(string $oid): bool;

    public function getSubject() : string;

    public function getPublicKeyDer(): string;

    public function getExtensionData(string $oid) : ?ByteBuffer;
}
