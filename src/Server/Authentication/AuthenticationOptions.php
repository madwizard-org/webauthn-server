<?php


namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Extension\ExtensionInputInterface;

class AuthenticationOptions
{
    /**
     * @var CredentialId[]
     */
    private $allowCredentials = [];

    /**
     * @var string|null
     */
    private $userVerification;

    /**
     * @var int|null
     */
    private $timeout;

    /**
     * @var ExtensionInputInterface[]|null
     */
    private $extensions;

    /**
     * User handle to load credentials from
     * @var UserHandle|null
     */
    private $allowUserHandle;

    public function __construct()
    {
    }

    public function allowUserHandle(UserHandle $userHandle)
    {
        $this->allowUserHandle = $userHandle;
    }

    /**
     * @return UserHandle|null
     */
    public function getAllowUserHandle(): ?UserHandle
    {
        return $this->allowUserHandle;
    }

    /**
     * @param CredentialId $credential
     */
    public function addAllowCredential(CredentialId $credential)
    {
        $this->allowCredentials[] = $credential;
    }

    /**
     * @return CredentialId[]
     */
    public function getAllowCredentials(): array
    {
        return $this->allowCredentials;
    }

    /**
     * @return null|string
     */
    public function getUserVerification(): ?string
    {
        return $this->userVerification;
    }

    public function setUserVerification(?string $value) :void
    {
        if ($value !== null && !UserVerificationRequirement::isValidValue($value)) {
            throw new WebAuthnException(sprintf('Value %s is not a valid UserVerificationRequirement', $value));
        }

        $this->userVerification = $value;
    }

    /**
     * @return int|null
     */
    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    /**
     * @param int|null $timeout
     */
    public function setTimeout(?int $timeout): void
    {
        $this->timeout = $timeout;
    }

    public function addExtensionInput(ExtensionInputInterface $input) // TODO move to trait? shared with Registration
    {
        if ($this->extensions === null) {
            $this->extensions = [];
        }
        $this->extensions[] = $input;
    }

    /**
     * @return ExtensionInputInterface[]|null
     */
    public function getExtensionInputs():?array
    {
        return $this->extensions;
    }
}
