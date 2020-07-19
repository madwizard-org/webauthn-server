<?php

namespace MadWizard\WebAuthn\Metadata\Source;

class MetadataServiceSource implements MetadataSourceInterface
{
    /**
     * @var string
     */
    private $url;

    /**
     * @var string
     */
    private $rootCert;

    /**
     * @var string|null
     */
    private $accessToken;

    public function __construct(string $url, string $rootCert, ?string $accessToken = null)
    {
        $this->url = $url;
        $this->rootCert = $rootCert;
        $this->accessToken = $accessToken;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function getRootCert(): string
    {
        return $this->rootCert;
    }

    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }
}
