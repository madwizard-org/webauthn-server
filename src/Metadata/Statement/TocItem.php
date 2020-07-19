<?php

namespace MadWizard\WebAuthn\Metadata\Statement;

use MadWizard\WebAuthn\Attestation\Identifier\IdentifierInterface;
use MadWizard\WebAuthn\Format\ByteBuffer;

class TocItem
{
    /**
     * @var IdentifierInterface
     */
    private $identifier;

    /**
     * @var ByteBuffer|null
     */
    private $hash;

    /**
     * @var string|null
     */
    private $url;

    /**
     * @var StatusReport[]
     */
    private $statusReports;

    /**
     * @param StatusReport[] $statusReports
     */
    public function __construct(IdentifierInterface $identifier, ?ByteBuffer $hash, ?string $url, array $statusReports)
    {
        $this->identifier = $identifier;
        $this->hash = $hash;
        $this->url = $url;
        $this->statusReports = $statusReports;
    }

    public function getIdentifier(): IdentifierInterface
    {
        return $this->identifier;
    }

    public function getHash(): ?ByteBuffer
    {
        return $this->hash;
    }

    public function getUrl(): ?string
    {
        return $this->url;
    }

    /**
     * @return StatusReport[]
     */
    public function getStatusReports(): array
    {
        return $this->statusReports;
    }
}
