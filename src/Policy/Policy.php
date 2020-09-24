<?php

namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ConfigurationException;

final class Policy implements PolicyInterface
{
    public const DEFAULT_CHALLENGE_LENGTH = 64;

    private const MIN_CHALLENGE_LENGTH = 32;

    private const SUPPORTED_ALGORITHMS = [
        CoseAlgorithm::ES256,
        CoseAlgorithm::ES384,
        CoseAlgorithm::ES512,
        CoseAlgorithm::RS256,
        CoseAlgorithm::RS384,
        CoseAlgorithm::RS512,
        CoseAlgorithm::RS1,
    ];

    private const DEFAULT_ALGORITHMS = [
        CoseAlgorithm::ES256,
        CoseAlgorithm::ES384,
        CoseAlgorithm::ES512,
        CoseAlgorithm::RS256,
        CoseAlgorithm::RS384,
        CoseAlgorithm::RS512,
    ];

    /**
     * @var bool
     */
    private $userPresenceRequired = true;

    /**
     * @var int
     */
    private $challengeLength = self::DEFAULT_CHALLENGE_LENGTH;

    /**
     * @var int[]
     */
    private $algorithms = self::DEFAULT_ALGORITHMS;

    public function __construct()
    {
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
    public function setUserPresenceRequired(bool $required): void
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
