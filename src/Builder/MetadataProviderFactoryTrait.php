<?php

namespace MadWizard\WebAuthn\Builder;

use MadWizard\WebAuthn\Cache\CacheProviderInterface;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Metadata\Provider\FileProvider;
use MadWizard\WebAuthn\Metadata\Provider\MetadataProviderInterface;
use MadWizard\WebAuthn\Metadata\Provider\MetadataServiceProvider;
use MadWizard\WebAuthn\Metadata\Source\MetadataServiceSource;
use MadWizard\WebAuthn\Metadata\Source\MetadataSourceInterface;
use MadWizard\WebAuthn\Metadata\Source\StatementDirectorySource;
use MadWizard\WebAuthn\Pki\ChainValidatorInterface;
use MadWizard\WebAuthn\Remote\DownloaderInterface;
use Psr\Log\LoggerAwareInterface;

trait MetadataProviderFactoryTrait
{
    abstract protected function buildDownloader(): DownloaderInterface;

    abstract protected function buildCacheProvider(): CacheProviderInterface;

    abstract protected function buildChainValidator(): ChainValidatorInterface;

    /**
     * @param MetadataSourceInterface[] $sources
     *
     * @return MetadataProviderInterface[]
     *
     * @throws UnsupportedException
     */
    private function createMetadataProviders(array $sources): array
    {
        $providers = [];
        foreach ($sources as $source) {
            if ($source instanceof StatementDirectorySource) {
                $provider = new FileProvider($source);
            } elseif ($source instanceof MetadataServiceSource) {
                $provider = new MetadataServiceProvider($source, $this->buildDownloader(), $this->buildCacheProvider(), $this->buildChainValidator());
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
}
