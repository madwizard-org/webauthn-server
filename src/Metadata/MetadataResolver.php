<?php

namespace MadWizard\WebAuthn\Metadata;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Metadata\Provider\MetadataProviderInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

final class MetadataResolver implements MetadataResolverInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    /**
     * @var MetadataProviderInterface[]
     */
    private $providers;

    public function __construct(array $providers)
    {
        $this->providers = $providers;
        $this->logger = new NullLogger();
    }

    public function getMetadata(RegistrationResultInterface $registrationResult): ?MetadataInterface
    {
        foreach ($this->providers as $provider) {
            try {
                $metadata = $provider->getMetadata($registrationResult);
                if ($metadata !== null) {
                    $this->logger->info('Found metadata for authenticator in provider {provider}.', ['provider' => $provider->getDescription()]);
                    return $metadata;
                }
            } catch (WebAuthnException $e) {
                $this->logger->warning('Error retrieving metadata ({error}) - ignoring provider {provider}.', ['error' => $e->getMessage(), 'provider' => $provider->getDescription(), 'exception' => $e]);
                continue;
            }
        }
        return null;
    }
}
