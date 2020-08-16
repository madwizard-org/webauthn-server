<?php

namespace MadWizard\WebAuthn\Builder;

use Closure;
use GuzzleHttp\Client;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustPathValidator;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustPathValidatorInterface;
use MadWizard\WebAuthn\Attestation\Verifier\AndroidKeyAttestationVerifier;
use MadWizard\WebAuthn\Attestation\Verifier\AndroidSafetyNetAttestationVerifier;
use MadWizard\WebAuthn\Attestation\Verifier\FidoU2fAttestationVerifier;
use MadWizard\WebAuthn\Attestation\Verifier\NoneAttestationVerifier;
use MadWizard\WebAuthn\Attestation\Verifier\PackedAttestationVerifier;
use MadWizard\WebAuthn\Attestation\Verifier\TpmAttestationVerifier;
use MadWizard\WebAuthn\Cache\CacheProviderInterface;
use MadWizard\WebAuthn\Cache\FileCacheProvider;
use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Metadata\MetadataResolver;
use MadWizard\WebAuthn\Metadata\MetadataResolverInterface;
use MadWizard\WebAuthn\Metadata\NullMetadataResolver;
use MadWizard\WebAuthn\Metadata\Provider\FileProvider;
use MadWizard\WebAuthn\Metadata\Provider\MetadataServiceProvider;
use MadWizard\WebAuthn\Metadata\Source\MetadataServiceSource;
use MadWizard\WebAuthn\Metadata\Source\MetadataSourceInterface;
use MadWizard\WebAuthn\Metadata\Source\StatementDirectorySource;
use MadWizard\WebAuthn\Pki\CertificateStatusResolver;
use MadWizard\WebAuthn\Pki\CertificateStatusResolverInterface;
use MadWizard\WebAuthn\Pki\ChainValidator;
use MadWizard\WebAuthn\Pki\ChainValidatorInterface;
use MadWizard\WebAuthn\Policy\Policy;
use MadWizard\WebAuthn\Policy\PolicyInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManager;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManagerInterface;
use MadWizard\WebAuthn\Policy\Trust\Voter\AllowEmptyMetadataVoter;
use MadWizard\WebAuthn\Policy\Trust\Voter\SupportedAttestationTypeVoter;
use MadWizard\WebAuthn\Policy\Trust\Voter\TrustAttestationTypeVoter;
use MadWizard\WebAuthn\Policy\Trust\Voter\TrustChainVoter;
use MadWizard\WebAuthn\Policy\Trust\Voter\UndesiredStatusReportVoter;
use MadWizard\WebAuthn\Remote\CachingClientFactory;
use MadWizard\WebAuthn\Remote\Downloader;
use MadWizard\WebAuthn\Remote\DownloaderInterface;
use MadWizard\WebAuthn\Server\ServerInterface;
use MadWizard\WebAuthn\Server\WebAuthnServer;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class ServerBuilder
{
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
     * @var LoggerInterface|null
     */
    private $logger;

    /**
     * @var bool
     */
    private $allowNoneAttestation = true;

    /**
     * @var bool
     */
    private $allowSelfAttestation = true;

    /**
     * @var bool
     */
    private $trustWithoutMetadata = true;

    /**
     * @var bool
     */
    private $useMetadata = true;

    public function __construct()
    {
    }

    // TODO: conistent set/with methods
    public function setRelyingParty(RelyingParty $rp): self
    {
        $this->rp = $rp;
        return $this;
    }

    public function setCredentialStore(CredentialStoreInterface $store): self
    {
        $this->store = $store;
        return $this;
    }

    public function setCacheDirectory(string $directory): self
    {
        $this->cacheDir = $directory;
        return $this;
    }

    public function useSystemTempCache(string $subDirectory = 'webauthn-server-cache'): self
    {
        $this->cacheDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $subDirectory;
        return $this;
    }

    /**
     * @param callable|PolicyCallbackInterface $policyCallback
     *
     * @return $this
     */
    public function configurePolicy(callable $policyCallback): self
    {
        $this->policyCallback = $policyCallback;
        return $this;
    }

//    public function withTrustPreset(string $preset)
//    {
//    }

    public function allowNoneAttestation(bool $allow): self
    {
        $this->allowNoneAttestation = $allow;
        return $this;
    }

    public function useMetadata(bool $use): self
    {
        $this->useMetadata = $use;
        return $this;
    }

    public function allowSelfAttestation(bool $allow): self
    {
        $this->allowSelfAttestation = $allow;
        return $this;
    }

    public function trustWithoutMetadata(bool $trust): self
    {
        $this->trustWithoutMetadata = $trust;
        return $this;
    }

    public function withLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    private function assignLogger(LoggerAwareInterface $service): void
    {
        if ($this->logger !== null) {
            $service->setLogger($this->logger);
        }
    }

    public function build(): ServerInterface
    {
        $c = $this->setupContainer();

        return $c[ServerInterface::class];
    }

    private function setupContainer(): ServiceContainer
    {
        $c = new ServiceContainer();

        $this->setupConfiguredServices($c);
        $this->setupFormats($c);
        $this->setupTrustDecisionManager($c);

        $c[TrustPathValidatorInterface::class] = static function (ServiceContainer $c) {
            return new TrustPathValidator($c[ChainValidatorInterface::class]);
        };

        $c[ChainValidatorInterface::class] = static function (ServiceContainer $c) {
            // TODO
            //return new ChainValidator($c[CertificateStatusResolverInterface::class]);
            return new ChainValidator(null);
        };

        // TODO
//        $c[CertificateStatusResolverInterface::class] = static function (ServiceContainer $c) {
//            return new CertificateStatusResolver($c[DownloaderInterface::class], $c[CacheProviderInterface::class]);
//        };

        $c[PolicyInterface::class] = Closure::fromCallable([$this, 'createPolicy']);
        $c[MetadataResolverInterface::class] = Closure::fromCallable([$this, 'createMetadataResolver']);
        $c[ServerInterface::class] = Closure::fromCallable([$this, 'createServer']);

        return $c;
    }

    private function setupDownloader(ServiceContainer $c)
    {
        $this->setupCache($c);
        if (isset($c[DownloaderInterface::class])) {
            return;
        }
        $c[DownloaderInterface::class] = static function (ServiceContainer $c) {
            return new Downloader($c[Client::class]);
        };
        $c[Client::class] = static function (ServiceContainer $c) {
            $factory = new CachingClientFactory($c[CacheProviderInterface::class]);
            return $factory->createClient();
        };
    }

    private function setupCache(ServiceContainer $c)
    {
        if (isset($c[CacheProviderInterface::class])) {
            return;
        }
        if ($this->cacheDir === null) {
            throw new ConfigurationException('No cache directory configured. Use useCacheDirectory or useSystemTempCache.');
        }
        $c[CacheProviderInterface::class] = function (ServiceContainer $c) {
            return new FileCacheProvider($this->cacheDir);
        };
    }

    private function setupConfiguredServices(ServiceContainer $c): void
    {
        if ($this->rp === null) {
            throw new ConfigurationException('Relying party not configured. Use setRelyingParty.');
        }

        $c[RelyingPartyInterface::class] = function () { return $this->rp; };

        if ($this->store === null) {
            throw new ConfigurationException('Credential store not configured. Use setCredentialStore.');
        }

        $c[CredentialStoreInterface::class] = function () { return $this->store; };
        $c[LoggerInterface::class] = function () { return $this->logger ?? new NullLogger(); };
    }

    private function createPolicy(ServiceContainer $c): PolicyInterface
    {
        $policy = new Policy(
            $c[RelyingPartyInterface::class],
            $c[MetadataResolverInterface::class],
            $c[TrustDecisionManagerInterface::class],
            $c[AttestationFormatRegistryInterface::class]
        );

        if ($this->policyCallback !== null) {
            ($this->policyCallback)($policy);
        }

        return $policy;
    }

    private function createServer(ServiceContainer $c): ServerInterface
    {
        return new WebAuthnServer($c[PolicyInterface::class], $c[CredentialStoreInterface::class]);
    }

    private function getRelyingParty(): RelyingPartyInterface
    {
        return $this->rp;
    }

    public function addMetadataSource(MetadataSourceInterface $metadataSource): self
    {
        $this->metadataSources[] = $metadataSource;
        return $this;
    }

    private function createMetadataResolver(ServiceContainer $c): MetadataResolverInterface
    {
        if (count($this->metadataSources) === 0) {
            return new NullMetadataResolver();
        }
        return new MetadataResolver($this->createMetadataProviders($c));
    }

    private function setupTrustDecisionManager(ServiceContainer $c)
    {
        $c[TrustDecisionManagerInterface::class] = function (ServiceContainer $c) {
            $tdm = new TrustDecisionManager();

            if ($this->allowNoneAttestation) {
                $tdm->addVoter(new TrustAttestationTypeVoter(AttestationType::NONE));
            }
            if ($this->allowSelfAttestation) {
                $tdm->addVoter(new TrustAttestationTypeVoter(AttestationType::SELF));
            }
            if ($this->trustWithoutMetadata) {
                $tdm->addVoter(new AllowEmptyMetadataVoter());
            }
            if ($this->useMetadata) {
                $tdm->addVoter(new SupportedAttestationTypeVoter());
                $tdm->addVoter(new UndesiredStatusReportVoter());
                $tdm->addVoter(new TrustChainVoter($c[TrustPathValidatorInterface::class]));
            }
            return $tdm;
        };
    }

    private function createMetadataProviders(ServiceContainer $c): array
    {
        $providers = [];
        foreach ($this->metadataSources as $source) {
            if ($source instanceof StatementDirectorySource) {
                $provider = new FileProvider($source);
            } elseif ($source instanceof MetadataServiceSource) {
                $this->setupDownloader($c);
                $provider = new MetadataServiceProvider($source, $c[DownloaderInterface::class], $c[CacheProviderInterface::class], $c[ChainValidatorInterface::class]);
            } else {
                throw new UnsupportedException(sprintf('No provider available for metadata source of type %s.', get_class($source)));
            }

            if ($provider instanceof LoggerAwareInterface) {
                $this->assignLogger($provider);
            }
            $providers[] = $provider;
        }
        return $providers;
    }

    private function setupFormats(ServiceContainer $c)
    {
        $c[PackedAttestationVerifier::class] = static function () {
            return new AndroidSafetyNetAttestationVerifier();
        };
        $c[FidoU2fAttestationVerifier::class] = static function () {
            return new FidoU2fAttestationVerifier();
        };
        $c[NoneAttestationVerifier::class] = static function () {
            return new NoneAttestationVerifier();
        };
        $c[TpmAttestationVerifier::class] = static function () {
            return new TpmAttestationVerifier();
        };
        $c[AndroidSafetyNetAttestationVerifier::class] = static function () {
            return new AndroidSafetyNetAttestationVerifier();
        };
        $c[AndroidKeyAttestationVerifier::class] = static function () {
            return new AndroidKeyAttestationVerifier();
        };

        $c[AttestationFormatRegistryInterface::class] = static function (ServiceContainer $c) {
            $registry = new AttestationFormatRegistry();

            $registry->addFormat($c[PackedAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[FidoU2fAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[NoneAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[TpmAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[AndroidSafetyNetAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[AndroidKeyAttestationVerifier::class]->getSupportedFormat());

            return $registry;
        };
    }
}
