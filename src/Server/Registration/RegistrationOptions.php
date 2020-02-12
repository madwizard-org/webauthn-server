<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Dom\AttestationConveyancePreference;
use MadWizard\WebAuthn\Dom\AuthenticatorSelectionCriteria;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Extension\ExtensionInputInterface;
use MadWizard\WebAuthn\Server\UserIdentityInterface;

class RegistrationOptions
{
    /**
     * @var string|null
     */
    private $attestation;

    /**
     * @var UserIdentityInterface
     */
    private $user;

    /**
     * @var AuthenticatorSelectionCriteria|null
     */
    private $authenticatorSelection;

    /**
     * @var ExtensionInputInterface[]|null
     */
    private $extensions;

    /**
     * @var bool|null
     */
    private $excludeExistingCredentials;

    public function __construct(UserIdentityInterface $user)
    {
        $this->user = $user;
    }

    /**
     * @return UserIdentityInterface
     */
    public function getUser(): UserIdentityInterface
    {
        return $this->user;
    }

    /**
     * @return null|string
     */
    public function getAttestation(): ?string
    {
        return $this->attestation;
    }

    /**
     * @param null|string $attestation
     */
    public function setAttestation(?string $attestation): void
    {
        if ($attestation !== null && !AttestationConveyancePreference::isValidValue($attestation)) {
            throw new ConfigurationException(sprintf('Value "%s" is not a valid attestation conveyance preference.', $attestation));
        }
        $this->attestation = $attestation;
    }

    public function setAuthenticatorSelection(?AuthenticatorSelectionCriteria $criteria)
    {
        $this->authenticatorSelection = $criteria;
    }

    /**
     * @return AuthenticatorSelectionCriteria|null
     */
    public function getAuthenticatorSelection(): ?AuthenticatorSelectionCriteria
    {
        return $this->authenticatorSelection;
    }

    public function addExtensionInput(ExtensionInputInterface $input)
    {
        if ($this->extensions === null) {
            $this->extensions = [];
        }
        $this->extensions[] = $input;
    }

    /**
     * @return null|bool
     */
    public function getExcludeExistingCredentials(): ?bool
    {
        return $this->excludeExistingCredentials;
    }

    /**
     * @param null|bool $excludeExistingCredentials     // TODO not null?
     */
    public function setExcludeExistingCredentials(?bool $excludeExistingCredentials): void
    {
        $this->excludeExistingCredentials = $excludeExistingCredentials;
    }

    /**
     * @return ExtensionInputInterface[]|null
     */
    public function getExtensionInputs():?array
    {
        return $this->extensions;
    }
}
