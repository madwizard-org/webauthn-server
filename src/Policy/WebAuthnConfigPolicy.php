<?php


namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInFormats;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustAnchorSet;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustAnchorSetInterface;
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

    /**
     * @var TrustAnchorSetInterface|null
     */
    private $trustAnchorSet;

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

    public function getTrustAnchorSet(): TrustAnchorSetInterface
    {
        if ($this->trustAnchorSet === null) {
            $this->trustAnchorSet = $this->createTrustAnchorSet();
        }
        return $this->trustAnchorSet;
    }

    private function createTrustAnchorSet() : TrustAnchorSetInterface
    {
        $set = new TrustAnchorSet();
        // TODO
        return $set;
    }
}
