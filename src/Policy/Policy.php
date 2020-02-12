<?php


namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInFormats;
use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Metadata\MetadataResolverInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManagerInterface;

final class Policy implements PolicyInterface
{
    /**
     * @var RelyingPartyInterface
     */
    private $relyingParty;

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

    /**
     * @var bool
     */
    private $userPresenceRequired = true;

    public function __construct(RelyingPartyInterface $relyingParty, MetadataResolverInterface $metadataResolver, TrustDecisionManagerInterface $trustDecisionManager)
    {
        $this->relyingParty = $relyingParty;
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

    public function getRelyingParty(): RelyingPartyInterface
    {
        return $this->relyingParty;
    }

    public function isUserPresenceRequired(): bool
    {
        return $this->userPresenceRequired;
    }

    /**
     * Set to false to allow silent authenticators (User Preset bit not set in authenticator data)
     * NOTE: setting this to false violates the WebAuthn specs but this option is needed to pass FIDO2 conformance, which
     * includes silent operations.
     * @param bool $required
     */
    public function setUserPresenceRequired(bool $required)
    {
        $this->userPresenceRequired = $required;
    }
}
