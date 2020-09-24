<?php

namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Server\Common\ExtensionInputsTrait;

final class AuthenticationOptions
{
    use ExtensionInputsTrait;

    /**
     * @var CredentialId[]
     */
    private $allowCredentials = [];

    /**
     * @var string
     */
    private $userVerification = UserVerificationRequirement::DEFAULT;

    /**
     * @var int|null
     */
    private $timeout;

    /**
     * User handle to load credentials from, or null for client side discoverable.
     *
     * @var UserHandle|null
     */
    private $userHandle;

    private function __construct(?UserHandle $userHandle)
    {
        $this->userHandle = $userHandle;
    }

    public static function createForUser(UserHandle $userHandle): self
    {
        return new self($userHandle);
    }

    public static function createForAnyUser(): self
    {
        return new self(null);
    }

    public function getUserHandle(): ?UserHandle
    {
        return $this->userHandle;
    }

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

    public function getUserVerification(): string
    {
        return $this->userVerification;
    }

    public function setUserVerification(string $value): void
    {
        if (!UserVerificationRequirement::isValidValue($value)) {
            throw new WebAuthnException(sprintf('Value %s is not a valid UserVerificationRequirement', $value));
        }

        $this->userVerification = $value;
    }

    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    public function setTimeout(?int $timeout): void
    {
        $this->timeout = $timeout;
    }
}
