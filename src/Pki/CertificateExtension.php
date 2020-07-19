<?php

namespace MadWizard\WebAuthn\Pki;

use MadWizard\WebAuthn\Format\ByteBuffer;

final class CertificateExtension
{
    /**
     * @var string
     */
    private $oid;

    /**
     * @var bool
     */
    private $critical;

    /**
     * @var ByteBuffer
     */
    private $value;

    public function __construct(string $oid, bool $critical, ByteBuffer $value)
    {
        $this->oid = $oid;
        $this->critical = $critical;
        $this->value = $value;
    }

    public function getOid(): string
    {
        return $this->oid;
    }

    public function isCritical(): bool
    {
        return $this->critical;
    }

    public function getValue(): ByteBuffer
    {
        return $this->value;
    }
}
