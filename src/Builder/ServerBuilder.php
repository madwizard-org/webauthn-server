<?php


namespace MadWizard\WebAuthn\Builder;

use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Metadata\MetadataResolver;
use MadWizard\WebAuthn\Metadata\MetadataResolverInterface;
use MadWizard\WebAuthn\Metadata\NullMetadataResolver;
use MadWizard\WebAuthn\Metadata\Source\MetadataSourceInterface;
use MadWizard\WebAuthn\Policy\Policy;
use MadWizard\WebAuthn\Policy\PolicyInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManager;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManagerInterface;
use MadWizard\WebAuthn\Server\ServerInterface;
use MadWizard\WebAuthn\Server\WebAuthnServer;

final class ServerBuilder
{

    // TODO:interface?
    // TODO:split in traits?
    /**
     * @var RelyingParty|null
     */
    private $rp;

    /**
     * @var CredentialStoreInterface|null
     */
    private $store;

    /**
     * @var string|null;
     */
    private $cacheDir;

    /**
     * @var MetadataSourceInterface[]
     */
    private $metadataSources = [];


    public function setRelyingParty(RelyingParty $rp) : self
    {
        $this->rp = $rp;
    }

    public function setCredentialStore(CredentialStoreInterface $store) : self
    {
        $this->store = $store;
    }

    public function setCacheDirectory(string $directory) : self
    {
        $this->cacheDir = $directory;
    }

    public function useSystemTempCache(string $subDirectory = 'webauthn-server-cache') : self
    {
        $this->cacheDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $subDirectory;
    }

    private function getCacheDirectory(): string
    {
        if ($this->cacheDir === null) {
            throw new ConfigurationException("No cache directory configured. Use useCacheDirectory or useSystemTempCache.");
        }
        return $this->cacheDir;
    }

    private function getCredentialStore() : CredentialStoreInterface
    {
        if ($this->store === null) {
            throw new ConfigurationException("Credential store not configured. Use setCredentialStore.");
        }

        return $this->store;
    }

    private function getPolicy(): PolicyInterface
    {
        return new Policy($this->getRelyingParty(), $this->getMetadataResolver(), $this->getTrustDecisionManager());
    }

    public function getServer() : ServerInterface
    {
        return new WebAuthnServer($this->getPolicy(), $this->getCredentialStore());
    }

    private function getRelyingParty(): RelyingPartyInterface
    {
        if ($this->rp === null) {
            throw new ConfigurationException("Relying party not configured. Use setRelyingParty.");
        }

        return $this->rp;
    }


    private function getMetadataResolver() : MetadataResolverInterface
    {
        if (count($this->metadataSources) === 0) {
            return new NullMetadataResolver();
        }

        $resolver = new MetadataResolver();


        // TODO

        return $resolver;
    }

    private function getTrustDecisionManager(): TrustDecisionManagerInterface
    {
        $tdm = new TrustDecisionManager();

        // TODO

        return $tdm;
    }
}
