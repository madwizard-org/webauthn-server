<?php


namespace MadWizard\WebAuthn\Dom;

use InvalidArgumentException;

class AuthenticatorSelectionCriteria extends AbstractDictionary
{
    /**
     * Platform attachment value from the AuthenticatorAttachment enumeration
     * @see AuthenticatorAttachment
     * @var string|null
     */
    private $authenticatorAttachment;

    /**
     * @var bool|null
     */
    private $requireResidentKey;

    /**
     * @see UserVerificationRequirement
     * @var string|null
     */
    private $userVerification;

    /**
     * @return null|string
     */
    public function getAuthenticatorAttachment(): ?string
    {
        return $this->authenticatorAttachment;
    }

    /**
     * @param null|string $authenticatorAttachment
     */
    public function setAuthenticatorAttachment(?string $value): void
    {
        if ($value !== null && !AuthenticatorAttachment::isValidValue($value)) {
            throw new InvalidArgumentException(sprintf('Value %s is not a valid AuthenticatorAttachment', $value));
        }
        $this->authenticatorAttachment = $value;
    }

    /**
     * @return bool|null
     */
    public function getRequireResidentKey(): ?bool
    {
        return $this->requireResidentKey;
    }

    /**
     * @param bool|null $requireResidentKey
     */
    public function setRequireResidentKey(?bool $value): void
    {
        $this->requireResidentKey = $value;
    }

    /**
     * @return null|string
     */
    public function getUserVerification(): ?string
    {
        return $this->userVerification;
    }

    /**
     * @param null|string $userVerification
     */
    public function setUserVerification(?string $value): void
    {
        if ($value !== null && !UserVerificationRequirement::isValidValue($value)) {
            throw new InvalidArgumentException(sprintf('Value %s is not a valid UserVerificationRequirement', $value));
        }
        $this->userVerification = $value;
    }

    public function getAsArray(): array
    {
        $map = [];
        if ($this->authenticatorAttachment !== null) {
            $map['authenticatorAttachment'] = $this->authenticatorAttachment;
        }

        if ($this->requireResidentKey !== null) {
            $map['requireResidentKey'] = $this->requireResidentKey;
        }
        if ($this->userVerification !== null) {
            $map['userVerification'] = $this->userVerification;
        }
        return $map;
    }
}
