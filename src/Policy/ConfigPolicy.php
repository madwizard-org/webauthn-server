<?php


namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInFormats;
use MadWizard\WebAuthn\Config\ConfigurationInterface;
use MadWizard\WebAuthn\Metadata\MetadataResolverInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManagerInterface;

class ConfigPolicy implements PolicyInterface
{
    /**
     * @var ConfigurationInterface
     */
    private $config;

    /**
     * @var AttestationFormatRegistryInterface|null
     */
    private $formatRegistry;

    /**
     * @var TrustDecisionManagerInterface
     */
    private $trustDecisionManager;

    /**
     * @var MetadataResolverInterface
     */
    private $metadataResolver;

    public function __construct(ConfigurationInterface $config, MetadataResolverInterface $metadataResolver, TrustDecisionManagerInterface $trustDecisionManager)
    {
        $this->config = $config;
        $this->metadataResolver = $metadataResolver;
        $this->trustDecisionManager = $trustDecisionManager;
    }

    public function getAttestationFormatRegistry(): AttestationFormatRegistryInterface
    {
        if ($this->formatRegistry === null) {
            $this->formatRegistry = $this->createDefaultFormatRegistry();
        }

        return $this->formatRegistry;
    }

    /**
     * @return AttestationFormatInterface[]
     */
    private function getAttestationFormats() : array
    {
        return BuiltInFormats::getSupportedFormats();
    }

    private function createDefaultFormatRegistry() : AttestationFormatRegistry
    {
        $registry = new AttestationFormatRegistry();
        $formats = $this->getAttestationFormats();
        foreach ($formats as $format) {
            $registry->addFormat($format);
        }
        return $registry;
    }

    public function getTrustDecisionManager(): TrustDecisionManagerInterface
    {
        return $this->trustDecisionManager;
    }

    public function getMetadataResolver(): MetadataResolverInterface
    {
        return $this->metadataResolver;
    }
}
