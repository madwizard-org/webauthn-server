<?php


namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInFormats;
use MadWizard\WebAuthn\Config\WebAuthnConfigurationInterface;

class WebAuthnConfigPolicy implements WebAuthnPolicyInterface
{
    /**
     * @var WebAuthnConfigurationInterface
     */
    private $config;

    /**
     * @var AttestationFormatRegistryInterface|null
     */
    private $formatRegistry;

    public function __construct(WebAuthnConfigurationInterface $config)
    {
        $this->config = $config;
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
}
