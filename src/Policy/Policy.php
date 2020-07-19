<?php

namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistryInterface;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInFormats;
use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ConfigurationException;
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

    public const DEFAULT_CHALLENGE_LENGTH = 64;

    private const MIN_CHALLENGE_LENGTH = 32;

    private const SUPPORTED_ALGORITHMS = [ // TODO MOVE?
        CoseAlgorithm::ES256,
        CoseAlgorithm::ES384,
        CoseAlgorithm::ES512,
        CoseAlgorithm::RS256,
        CoseAlgorithm::RS384,
        CoseAlgorithm::RS512,
    ];

    /**
     * @var int
     */
    private $challengeLength = self::DEFAULT_CHALLENGE_LENGTH;

    /**
     * @var int[]
     */
    private $algorithms = self::SUPPORTED_ALGORITHMS;

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
    private function getAttestationFormats(): array
    {
        return BuiltInFormats::getSupportedFormats();
    }

    private function createDefaultFormatRegistry(): AttestationFormatRegistry
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
     */
    public function setUserPresenceRequired(bool $required)
    {
        $this->userPresenceRequired = $required;
    }

    public function getChallengeLength(): int
    {
        return $this->challengeLength;
    }

    public function setChallengeLength(int $challengeLength): void
    {
        if ($challengeLength < self::MIN_CHALLENGE_LENGTH) {
            throw new ConfigurationException(sprintf('Challenge should be at least of length %d.', self::MIN_CHALLENGE_LENGTH));
        }
        $this->challengeLength = $challengeLength;
    }

    /**
     * Sets which algorithms are allowed for the credentials that are created. Array of constants from the COSEAlgorithm
     * enumeration (e.g. COSEAlgorithm::ES256).
     *
     * @param int[] $algorithms
     *
     * @throws ConfigurationException
     *
     * @see CoseAlgorithm
     */
    public function setAllowedAlgorithms(array $algorithms): void
    {
        $validList = [];
        foreach ($algorithms as $algorithm) {
            if (!\is_int($algorithm)) {
                throw new ConfigurationException('Algorithms should be integer constants from the COSEAlgorithm enumeratons.');
            }

            if (!\in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
                throw new ConfigurationException(sprintf('Unsupported algorithm "%d".', $algorithm));
            }
            $validList[] = $algorithm;
        }
        $this->algorithms = $validList;
    }

    /**
     * @return int[]
     */
    public function getAllowedAlgorithms(): array
    {
        return $this->algorithms;
    }
}
