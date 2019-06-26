<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

class TrustStatus
{
    /**
     * @var bool
     */
    private $isTrusted;

    /**
     * @var MetadataInterface|null
     */
    private $metadata;

    private function __construct(bool $isTrusted, ?MetadataInterface $metadata = null)
    {
        $this->isTrusted = $isTrusted;
        $this->metadata = $metadata;
    }

    /**
     * @return bool
     */
    public function isTrusted(): bool
    {
        return $this->isTrusted;
    }

    /**
     * @return MetadataInterface|null
     */
    public function getMetadata(): ?MetadataInterface
    {
        return $this->metadata;
    }

    public static function notTrusted() : TrustStatus
    {
        return new TrustStatus(false);
    }

    public static function trusted(?MetadataInterface $metadata = null) : TrustStatus
    {
        return new TrustStatus(true, $metadata);
    }
}
