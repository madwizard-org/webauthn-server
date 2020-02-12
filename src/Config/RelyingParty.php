<?php


namespace MadWizard\WebAuthn\Config;

use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Web\Origin;

class RelyingParty implements RelyingPartyInterface
{
    /**
     * @var string Relying party name
     */
    private $name;

    /**
     * @var Origin Relying party's origin, e.g. https://example.com
     */
    private $origin;

    /**
     * @var string|null Relying party ID (domain string)
     */
    private $id;

    /**
     * @var string|null Relying party icon
     */
    private $iconUrl;

    public function __construct(string $name, string $origin)
    {
        $this->name = $name;
        $this->origin = Origin::parse($origin);
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @param string $rpName
     */
    public function setName(string $rpName): void
    {
        $this->name = $rpName;
    }

    /**
     * Returns the configured RelyingParty
     * @return null|string
     */
    public function getId(): ?string
    {
        return $this->id;
    }

    public function getEffectiveId() : string
    {
        if ($this->id !== null) {
            return $this->id;
        }

        return $this->origin->getHost();
    }

    /**
     * @param null|string $rpId A valid domain string that identifies the Relying Party
     * on whose behalf a given registration or authentication ceremony is being performed
     * @throws ConfigurationException if rpId is not a valid domain name
     * @see https://www.w3.org/TR/webauthn/#relying-party-identifier
     */
    public function setId(?string $rpId): void
    {
        if ($rpId !== null) {
            $rpId = filter_var($rpId, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
            if ($rpId === false) {
                throw new ConfigurationException(sprintf("Relying party ID '%s' is not a valid domain name.", $rpId));
            }
        }
        $this->id = $rpId;
    }

    /**
     * @return string|null
     */
    public function getIconUrl(): ?string
    {
        return $this->iconUrl;
    }

    public function setIconUrl(?string $url) : void
    {
        // TODO: FILTER_VALIDATE_URL does not allow data urls
//        if ($url !== null && filter_var($url, FILTER_VALIDATE_URL) === false) {
//            throw new ConfigurationException("Invalid relying party icon url.");
//        }
        $this->iconUrl = $url;
    }

    public function setOrigin(string $origin)
    {
        try {
            $this->origin = Origin::parse($origin);
        } catch (ParseException $e) {
            throw new ConfigurationException(sprintf("Invalid origin '%s'.", $origin), 0, $e);
        }
    }

    public function getOrigin() : Origin
    {
        return $this->origin;
    }
}
