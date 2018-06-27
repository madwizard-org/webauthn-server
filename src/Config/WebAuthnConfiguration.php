<?php


namespace MadWizard\WebAuthn\Config;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialRpEntity;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Web\Origin;

class WebAuthnConfiguration
{
    public const DEFAULT_CHALLENGE_LENGTH = 64;

    private const MIN_CHALLENGE_LENGTH = 32;

    /**
     * @var string|null Relying party ID (domain string)
     */
    private $rpId;

    /**
     * @var string|null Relying party name
     */
    private $rpName;

    /**
     * @var Origin|null Relying party's origin, e.g. https://example.com
     */
    private $rpOrigin;

    /**
     * @var int
     */
    private $challengeLength = self::DEFAULT_CHALLENGE_LENGTH;

    public function __construct()
    {
    }

    /**
     * Returns the configurated RelyingParty
     * @return null|string
     */
    public function getRelyingPartyId(): ?string
    {
        return $this->rpId;
    }

    public function getEffectiveReyingPartyId() : string
    {
        if ($this->rpId !== null) {
            return $this->rpId;
        }

        if ($this->rpOrigin !== null) {
            return $this->rpOrigin->getDomain();
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
            throw new ConfigurationException('Relying party name should be set with setRelyingPartyId.');
        }
        return new PublicKeyCredentialRpEntity($this->rpName, $this->rpId);
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
}
