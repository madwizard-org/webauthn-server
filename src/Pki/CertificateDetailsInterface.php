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
}
