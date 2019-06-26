<?php


namespace MadWizard\WebAuthn\Config;

use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRpEntity;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Web\Origin;

class WebAuthnConfiguration implements WebAuthnConfigurationInterface
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
    ];

    /**
     * @var string|null Relying party ID (domain string)
     */
    private $rpId;

    /**
     * @var string|null Relying party name
     */
    private $rpName;

    /**
     * @var string|null Relying party icon
     */
    private $rpIconUrl;

    /**
     * @var Origin|null Relying party's origin, e.g. https://example.com
     */
    private $rpOrigin;

    /**
     * @var int
     */
    private $challengeLength = self::DEFAULT_CHALLENGE_LENGTH;

    /**
     * @var int[]
     */
    private $algorithms = self::SUPPORTED_ALGORITHMS;

    public function __construct()
    {
    }

    /**
     * Returns the configured RelyingParty
     * @return null|string
     */
    public function getRelyingPartyId(): ?string
    {
        return $this->rpId;
    }

    public function getEffectiveRelyingPartyId() : string
    {
        if ($this->rpId !== null) {
            return $this->rpId;
        }

        if ($this->rpOrigin !== null) {
            return $this->rpOrigin->getHost();
        }

        throw new ConfigurationException('Relying party id could not be determined from configuration.');
    }

    /**
     * @param null|string $rpName
     */
    public function setRelyingPartyName(?string $rpName): void
    {
        $this->rpName = $rpName;
    }

    /**
     * @param null|string $rpId A valid domain string that identifies the Relying Party
     * on whose behalf a given registration or authentication ceremony is being performed
     * @throws ConfigurationException if rpId is not a valid domain name
     * @see https://www.w3.org/TR/webauthn/#relying-party-identifier
     */
    public function setRelyingPartyId(?string $rpId): void
    {
        if ($rpId !== null) {
            $rpId = filter_var($rpId, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
            if ($rpId === false) {
                throw new ConfigurationException(sprintf("Relying party ID '%s' is not a valid domain name.", $rpId));
            }
        }
        $this->rpId = $rpId;
    }

    public function getRelyingPartyEntity() : PublicKeyCredentialRpEntity
    {
        if ($this->rpName === null) {
            throw new ConfigurationException('Relying party name should be set with setRelyingPartyName.');
        }
        $rpEntity = new PublicKeyCredentialRpEntity($this->rpName, $this->rpId);
        if ($this->rpIconUrl !== null) {
            $rpEntity->setIcon($this->rpIconUrl);
        }
        return $rpEntity;
    }

    public function setRelyingPartyOrigin(?string $origin)
    {
        if ($origin === null) {
            $this->rpOrigin = null;
            return;
        }
        try {
            $this->rpOrigin = Origin::parse($origin);
        } catch (ParseException $e) {
            throw new ConfigurationException(sprintf("Invalid origin '%s'.", $origin), 0, $e);
        }
    }

    public function getRelyingPartyOrigin() : ?Origin
    {
        return $this->rpOrigin;
    }

    /**
     * @return int
     */
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
     * enumeration (e.g. COSEAlgorithm::ES256)
     * @param int[] $algorithms
     * @throws ConfigurationException
     * @see CoseAlgorithm
     */
    public function setAllowedAlgorithms(array $algorithms) : void
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
    public function getAllowedAlgorithms() : array
    {
        return $this->algorithms;
    }

    public function setRelyingPartyIconUrl(?string $url) : void
    {
        // TODO: FILTER_VALIDATE_URL does not allow data urls
//        if ($url !== null && filter_var($url, FILTER_VALIDATE_URL) === false) {
//            throw new ConfigurationException("Invalid relying party icon url.");
//        }
        $this->rpIconUrl = $url;
    }

    public function getRelyingPartyIconUrl(): ?string
    {
        return $this->rpIconUrl;
    }
}
