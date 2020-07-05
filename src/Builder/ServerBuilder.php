<?php


namespace MadWizard\WebAuthn\Builder;

use GuzzleHttp\Client;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustPathValidator;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustPathValidatorInterface;
use MadWizard\WebAuthn\Cache\CacheProviderInterface;
use MadWizard\WebAuthn\Cache\FileCacheProvider;
use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Metadata\MetadataResolver;
use MadWizard\WebAuthn\Metadata\MetadataResolverInterface;
use MadWizard\WebAuthn\Metadata\NullMetadataResolver;
use MadWizard\WebAuthn\Metadata\Source\MetadataSourceInterface;
use MadWizard\WebAuthn\Pki\CertificateStatusResolverInterface;
use MadWizard\WebAuthn\Pki\ChainValidator;
use MadWizard\WebAuthn\Pki\ChainValidatorInterface;
use MadWizard\WebAuthn\Policy\Policy;
use MadWizard\WebAuthn\Policy\PolicyInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManager;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManagerInterface;
use MadWizard\WebAuthn\Policy\Trust\Voter\AnyTrustVoter;
use MadWizard\WebAuthn\Policy\Trust\Voter\SupportedAttestationTypeVoter;
use MadWizard\WebAuthn\Policy\Trust\Voter\TrustAttestationTypeVoter;
use MadWizard\WebAuthn\Policy\Trust\Voter\TrustChainVoter;
use MadWizard\WebAuthn\Policy\Trust\Voter\UndesiredStatusReportVoter;
use MadWizard\WebAuthn\Remote\CachingClientFactory;
use MadWizard\WebAuthn\Remote\Downloader;
use MadWizard\WebAuthn\Remote\DownloaderInterface;
use MadWizard\WebAuthn\Server\ServerInterface;
use MadWizard\WebAuthn\Server\WebAuthnServer;

final class ServerBuilder
{
    use MetadataProviderFactoryTrait;

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
     * @var callable|PolicyCallbackInterface|null
     */
    private $policyCallback;

    /**
     * @var MetadataSourceInterface[]
     */
    private $metadataSources = [];

    /**
     * @var DownloaderInterface|null
     */
    private $downloader;

    /**
     * @var Client|null
     */
    private $httpClient;

    /**
     * @var CacheProviderInterface|null
     */
    private $cacheProvider;

    /**
     * @var ChainValidatorInterface|null
     */
    private $chainValidator;

    public function __construct()
    {
    }

    private function reset()
    {
        $this->downloader = null;
        $this->httpClient = null;
        $this->cacheProvider = null;
        $this->chainValidator = null;
    }

    public function setRelyingParty(RelyingParty $rp) : self
    {
        $this->rp = $rp;
        return $this;
    }

    public function setCredentialStore(CredentialStoreInterface $store) : self
    {
        $this->store = $store;
        return $this;
    }

    public function setCacheDirectory(string $directory) : self
    {
        $this->cacheDir = $directory;
        return $this;
    }

    public function useSystemTempCache(string $subDirectory = 'webauthn-server-cache') : self
    {
        $this->cacheDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $subDirectory;
        return $this;
    }

    private function getCacheDirectory(): string
    {
        if ($this->cacheDir === null) {
            throw new ConfigurationException('No cache directory configured. Use useCacheDirectory or useSystemTempCache.');
        }
        return $this->cacheDir;
    }

    private function getCredentialStore() : CredentialStoreInterface
    {
        if ($this->store === null) {
            throw new ConfigurationException('Credential store not configured. Use setCredentialStore.');
        }

        return $this->store;
    }

    /**
     * @param callable|PolicyCallbackInterface $policyCallback
     * @return $this
     */
    public function configurePolicy(callable $policyCallback): self
    {
        $this->policyCallback = $policyCallback;
        return $this;
    }

    private function getPolicy(): PolicyInterface
    {
        $policy = new Policy($this->getRelyingParty(), $this->getMetadataResolver(), $this->getTrustDecisionManager());

        if ($this->policyCallback !== null) {
            ($this->policyCallback)($policy);
        }

        return $policy;
    }

    public function build() : ServerInterface
    {
        $this->reset();
        try {
            return new WebAuthnServer($this->getPolicy(), $this->getCredentialStore());
        } finally {
            $this->reset();
        }
    }

    private function getRelyingParty(): RelyingPartyInterface
    {
        if ($this->rp === null) {
            throw new ConfigurationException('Relying party not configured. Use setRelyingParty.');
        }

        return $this->rp;
    }

    public function addMetadataSource(MetadataSourceInterface $metadataSource): self
    {
        $this->metadataSources[] = $metadataSource;
        return $this;
    }

    private function getMetadataResolver() : MetadataResolverInterface
    {
        if (count($this->metadataSources) === 0) {
            return new NullMetadataResolver();
        }
        return new MetadataResolver($this->createMetadataProviders($this->metadataSources));
    }

    private function getTrustDecisionManager(): TrustDecisionManagerInterface
    {
        $tdm = new TrustDecisionManager();

        // TODO
        //$tdm->addVoter(new AnyTrustVoter());

        $tdm->addVoter(new SupportedAttestationTypeVoter());
        $tdm->addVoter(new TrustAttestationTypeVoter('None'));
        $tdm->addVoter(new TrustAttestationTypeVoter('Self'));
        $tdm->addVoter(new UndesiredStatusReportVoter());
        $tdm->addVoter(new TrustChainVoter($this->getTrustPathValidator()));

        return $tdm;
    }

    private function getTrustPathValidator(): TrustPathValidatorInterface
    {
        return new TrustPathValidator($this->buildChainValidator());
    }

    private function buildDownloader() :DownloaderInterface
    {
        if ($this->downloader === null) {
            $this->downloader = new Downloader($this->buildHttpClient());
        }
        return $this->downloader;
    }

    private function buildCacheProvider(): CacheProviderInterface
    {
        if ($this->cacheProvider === null) {
            $this->cacheProvider = new FileCacheProvider($this->getCacheDirectory());
        }
        return $this->cacheProvider;
    }

    private function buildChainValidator(): ChainValidatorInterface
    {
        if ($this->chainValidator === null) {
            $this->chainValidator = new ChainValidator($this->buildStatusResolver());
        }
        return $this->chainValidator;
    }

    private function buildHttpClient(): Client
    {
        if ($this->httpClient === null) {
            $factory = new CachingClientFactory($this->buildCacheProvider());
            $this->httpClient = $factory->createClient();
        }
        return $this->httpClient;
    }

    private function buildStatusResolver(): ?CertificateStatusResolverInterface
    {
        // TODO: IMPLEMENT
        return null;
    }
}
