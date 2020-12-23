<?php

namespace MadWizard\WebAuthn\Builder;

use Closure;
use GuzzleHttp\Client;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustPathValidator;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustPathValidatorInterface;
use MadWizard\WebAuthn\Attestation\Verifier;
use MadWizard\WebAuthn\Cache\CacheProviderInterface;
use MadWizard\WebAuthn\Cache\FileCacheProvider;
use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Extension\AppId\AppIdExtension;
use MadWizard\WebAuthn\Extension\ExtensionInterface;
use MadWizard\WebAuthn\Extension\ExtensionRegistry;
use MadWizard\WebAuthn\Extension\ExtensionRegistryInterface;
use MadWizard\WebAuthn\Metadata\MetadataResolver;
use MadWizard\WebAuthn\Metadata\MetadataResolverInterface;
use MadWizard\WebAuthn\Metadata\NullMetadataResolver;
use MadWizard\WebAuthn\Metadata\Provider\FileProvider;
use MadWizard\WebAuthn\Metadata\Provider\MetadataServiceProvider;
use MadWizard\WebAuthn\Metadata\Source\BundledSource;
use MadWizard\WebAuthn\Metadata\Source\MetadataServiceSource;
use MadWizard\WebAuthn\Metadata\Source\MetadataSourceInterface;
use MadWizard\WebAuthn\Metadata\Source\StatementDirectorySource;
use MadWizard\WebAuthn\Pki\CertificateStatusResolverInterface;
use MadWizard\WebAuthn\Pki\ChainValidator;
use MadWizard\WebAuthn\Pki\ChainValidatorInterface;
use MadWizard\WebAuthn\Pki\CrlCertificateStatusResolver;
use MadWizard\WebAuthn\Pki\NullCertificateStatusResolver;
use MadWizard\WebAuthn\Policy\Policy;
use MadWizard\WebAuthn\Policy\PolicyInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManager;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManagerInterface;
use MadWizard\WebAuthn\Policy\Trust\Voter;
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
    private $validateUsingMetadata = true;

    /**
     * @var bool
     */
    private $strictSupportedFormats = false;

    /**
     * @var string[]
     */
    private $enabledExtensions = [];

    /**
     * @var ExtensionInterface[]
     */
    private $customExtensions = [];

    /**
     * @var bool
     */
    private $enableCrl = false;

    /**
     * @var bool
     */
    private $crlSilentFailure = true;

    private const SUPPORTED_EXTENSIONS = [
        'appid' => AppIdExtension::class,
    ];

    public function __construct()
    {
    }

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

    /**
     * @return $this
     */
    public function allowNoneAttestation(bool $allow): self
    {
        $this->allowNoneAttestation = $allow;
        return $this;
    }

    /**
     * @return $this
     */
    public function strictSupportedFormats(bool $strict): self
    {
        $this->strictSupportedFormats = $strict;
        return $this;
    }

    /**
     * @return $this
     */
    public function validateUsingMetadata(bool $use): self
    {
        $this->validateUsingMetadata = $use;
        return $this;
    }

    /**
     * @return $this
     * @experimental
     */
    public function enableCrl(bool $enable, bool $silentFailure = true): self
    {
        if ($enable && !class_exists(\phpseclib3\File\X509::class)) {
            throw new UnsupportedException('CRL support requires phpseclib v3. Use composer require phpseclib/phpseclib ^3.0');
        }
        $this->enableCrl = $enable;
        $this->crlSilentFailure = $silentFailure;
        return $this;
    }

    /**
     * @return $this
     */
    public function allowSelfAttestation(bool $allow): self
    {
        $this->allowSelfAttestation = $allow;
        return $this;
    }

    /**
     * @return $this
     */
    public function trustWithoutMetadata(bool $trust): self
    {
        $this->trustWithoutMetadata = $trust;
        return $this;
    }

    /**
     * @return $this
     */
    public function enableExtensions(string ...$extensions): self
    {
        foreach ($extensions as $ext) {
            if (!isset(self::SUPPORTED_EXTENSIONS[$ext])) {
                throw new ConfigurationException(sprintf('Extension %s is not supported.', $ext));
            }
        }
        $this->enabledExtensions = array_merge($this->enabledExtensions, $extensions);
        return $this;
    }

    /**
     * @return $this
     */
    public function addCustomExtension(ExtensionInterface $extension): self
    {
        $this->customExtensions[] = $extension;
        return $this;
    }

    /**
     * @return $this
     */
    public function setLogger(LoggerInterface $logger): self
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
        $this->setupExtensions($c);

        $c[TrustPathValidatorInterface::class] = static function (ServiceContainer $c): TrustPathValidatorInterface {
            return new TrustPathValidator($c[ChainValidatorInterface::class]);
        };

        if ($this->enableCrl) {
            $this->setupCache($c);
            $this->setupDownloader($c);
            $c[CertificateStatusResolverInterface::class] = function (ServiceContainer $c): CertificateStatusResolverInterface {
                return new CrlCertificateStatusResolver($c[DownloaderInterface::class], $c[CacheProviderInterface::class], $this->crlSilentFailure);
            };
        } else {
            $c[CertificateStatusResolverInterface::class] = static function (): CertificateStatusResolverInterface {
                return new NullCertificateStatusResolver();
            };
        }

        $c[ChainValidatorInterface::class] = function (ServiceContainer $c): ChainValidatorInterface {
            return new ChainValidator($c[CertificateStatusResolverInterface::class]);
        };

        $c[PolicyInterface::class] = Closure::fromCallable([$this, 'createPolicy']);
        $c[MetadataResolverInterface::class] = Closure::fromCallable([$this, 'createMetadataResolver']);
        $c[ServerInterface::class] = Closure::fromCallable([$this, 'createServer']);

        return $c;
    }

    private function setupDownloader(ServiceContainer $c): void
    {
        $this->setupCache($c);
        if (isset($c[DownloaderInterface::class])) {
            return;
        }
        $c[DownloaderInterface::class] = static function (ServiceContainer $c): DownloaderInterface {
            return new Downloader($c[Client::class]);
        };
        $c[Client::class] = static function (ServiceContainer $c): Client {
            $factory = new CachingClientFactory($c[CacheProviderInterface::class]);
            return $factory->createClient();
        };
    }

    private function setupCache(ServiceContainer $c): void
    {
        if (isset($c[CacheProviderInterface::class])) {
            return;
        }

        $cacheDir = $this->cacheDir;
        if ($cacheDir === null) {
            throw new ConfigurationException('No cache directory configured. Use useCacheDirectory or useSystemTempCache.');
        }
        $c[CacheProviderInterface::class] = static function (ServiceContainer $c) use ($cacheDir): CacheProviderInterface {
            return new FileCacheProvider($cacheDir);
        };
    }

    private function setupConfiguredServices(ServiceContainer $c): void
    {
        if ($this->rp === null) {
            throw new ConfigurationException('Relying party not configured. Use setRelyingParty.');
        }

        $c[RelyingPartyInterface::class] = function (): RelyingPartyInterface { return $this->rp; };

        if ($this->store === null) {
            throw new ConfigurationException('Credential store not configured. Use setCredentialStore.');
        }

        $c[CredentialStoreInterface::class] = function (): CredentialStoreInterface { return $this->store; };
        $c[LoggerInterface::class] = function (): LoggerInterface { return $this->logger ?? new NullLogger(); };
    }

    private function createPolicy(ServiceContainer $c): PolicyInterface
    {
        $policy = new Policy();

        if ($this->policyCallback !== null) {
            ($this->policyCallback)($policy);
        }

        return $policy;
    }

    private function createServer(ServiceContainer $c): ServerInterface
    {
        return new WebAuthnServer(
            $c[RelyingPartyInterface::class],
            $c[PolicyInterface::class],
            $c[CredentialStoreInterface::class],
            $c[AttestationFormatRegistryInterface::class],
            $c[MetadataResolverInterface::class],
            $c[TrustDecisionManagerInterface::class],
            $c[ExtensionRegistryInterface::class]);
    }

    public function addMetadataSource(MetadataSourceInterface $metadataSource): self
    {
        $this->metadataSources[] = $metadataSource;
        return $this;
    }

    public function addBundledMetadataSource(array $sets = ['@all']): self
    {
        $this->metadataSources[] = new BundledSource($sets);
        return $this;
    }

    private function createMetadataResolver(ServiceContainer $c): MetadataResolverInterface
    {
        if (count($this->metadataSources) === 0) {
            return new NullMetadataResolver();
        }
        return new MetadataResolver($this->createMetadataProviders($c));
    }

    private function setupTrustDecisionManager(ServiceContainer $c): void
    {
        $c[TrustDecisionManagerInterface::class] = function (ServiceContainer $c): TrustDecisionManagerInterface {
            $tdm = new TrustDecisionManager();

            if ($this->allowNoneAttestation) {
                $tdm->addVoter(new Voter\TrustAttestationTypeVoter(AttestationType::NONE));
            }
            if ($this->allowSelfAttestation) {
                $tdm->addVoter(new Voter\TrustAttestationTypeVoter(AttestationType::SELF));
            }
            if ($this->trustWithoutMetadata) {
                $tdm->addVoter(new Voter\AllowEmptyMetadataVoter());
            }
            if ($this->validateUsingMetadata) {
                $tdm->addVoter(new Voter\SupportedAttestationTypeVoter());
                $tdm->addVoter(new Voter\UndesiredStatusReportVoter());
                $tdm->addVoter(new Voter\TrustChainVoter($c[TrustPathValidatorInterface::class]));
            }
            return $tdm;
        };
    }

    private function createMetadataProviders(ServiceContainer $c): array
    {
        $providers = [];
        foreach ($this->metadataSources as $source) {
            // TODO: More elegant solution than if/else
            if ($source instanceof StatementDirectorySource) {
                $providers[] = new FileProvider($source);
            } elseif ($source instanceof MetadataServiceSource) {
                $this->setupDownloader($c);
                $providers[] = new MetadataServiceProvider($source, $c[DownloaderInterface::class], $c[CacheProviderInterface::class], $c[ChainValidatorInterface::class]);
            } elseif ($source instanceof BundledSource) {
                $providers = array_merge(
                    $providers,
                    $source->createProviders()
                );
            } else {
                throw new UnsupportedException(sprintf('No provider available for metadata source of type %s.', get_class($source)));
            }
        }

        foreach ($providers as $provider) {
            if ($provider instanceof LoggerAwareInterface) {
                $this->assignLogger($provider);
            }
        }
        return $providers;
    }

    private function setupFormats(ServiceContainer $c): void
    {
        $c[Verifier\PackedAttestationVerifier::class] = static function (): Verifier\PackedAttestationVerifier {
            return new Verifier\PackedAttestationVerifier();
        };
        $c[Verifier\FidoU2fAttestationVerifier::class] = static function (): Verifier\FidoU2fAttestationVerifier {
            return new Verifier\FidoU2fAttestationVerifier();
        };
        $c[Verifier\NoneAttestationVerifier::class] = static function (): Verifier\NoneAttestationVerifier {
            return new Verifier\NoneAttestationVerifier();
        };
        $c[Verifier\TpmAttestationVerifier::class] = static function (): Verifier\TpmAttestationVerifier {
            return new Verifier\TpmAttestationVerifier();
        };
        $c[Verifier\AndroidSafetyNetAttestationVerifier::class] = static function (): Verifier\AndroidSafetyNetAttestationVerifier {
            return new Verifier\AndroidSafetyNetAttestationVerifier();
        };
        $c[Verifier\AndroidKeyAttestationVerifier::class] = static function (): Verifier\AndroidKeyAttestationVerifier {
            return new Verifier\AndroidKeyAttestationVerifier();
        };
        $c[Verifier\AppleAttestationVerifier::class] = static function (): Verifier\AppleAttestationVerifier {
            return new Verifier\AppleAttestationVerifier();
        };

        $c[AttestationFormatRegistryInterface::class] = function (ServiceContainer $c): AttestationFormatRegistryInterface {
            $registry = new AttestationFormatRegistry();

            $registry->strictSupportedFormats($this->strictSupportedFormats);

            $registry->addFormat($c[Verifier\PackedAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[Verifier\FidoU2fAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[Verifier\NoneAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[Verifier\TpmAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[Verifier\AndroidSafetyNetAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[Verifier\AndroidKeyAttestationVerifier::class]->getSupportedFormat());
            $registry->addFormat($c[Verifier\AppleAttestationVerifier::class]->getSupportedFormat());

            return $registry;
        };
    }

    private function setupExtensions(ServiceContainer $c): void
    {
        $c[AppIdExtension::class] = static function (ServiceContainer $c): AppIdExtension {
            return new AppIdExtension();
        };
        $c[ExtensionRegistryInterface::class] = function (ServiceContainer $c): ExtensionRegistryInterface {
            $registry = new ExtensionRegistry();
            foreach (array_unique($this->enabledExtensions) as $ext) {
                $registry->addExtension($c[self::SUPPORTED_EXTENSIONS[$ext]]);
            }
            foreach ($this->customExtensions as $ext) {
                $registry->addExtension($ext);
            }
            return $registry;
        };
    }
}
