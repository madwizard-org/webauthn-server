<?php

namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Dom\AttestationConveyancePreference;
use MadWizard\WebAuthn\Dom\AuthenticatorSelectionCriteria;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Server\Common\ExtensionInputsTrait;
use MadWizard\WebAuthn\Server\UserIdentityInterface;

final class RegistrationOptions     // TODO: add timeout (via trait?)
{
    use ExtensionInputsTrait;

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
     * @var bool
     */
    private $excludeExistingCredentials = false;

    private function __construct(UserIdentityInterface $userIdentity)
    {
        $this->user = $userIdentity;
    }

    public static function createForUser(UserIdentityInterface $userIdentity): self
    {
        return new RegistrationOptions($userIdentity);
    }

    public function getUser(): UserIdentityInterface
    {
        return $this->user;
    }

    public function getAttestation(): ?string
    {
        return $this->attestation;
    }

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

    public function getAuthenticatorSelection(): ?AuthenticatorSelectionCriteria
    {
        return $this->authenticatorSelection;
    }

    public function getExcludeExistingCredentials(): bool
    {
        return $this->excludeExistingCredentials;
    }

    public function setExcludeExistingCredentials(bool $excludeExistingCredentials): void
    {
        $this->excludeExistingCredentials = $excludeExistingCredentials;
    }
}
