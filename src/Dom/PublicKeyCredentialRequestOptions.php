<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;

class PublicKeyCredentialRequestOptions extends AbstractDictionary
{
    /**
     * @var ByteBuffer
     */
    private $challenge;

    /**
     * @var int|null
     */
    private $timeout;

    /**
     * @var string|null
     */
    private $rpId;

    /**
     * @var PublicKeyCredentialDescriptor[]|null
     */
    private $allowCredentials;

    /**
     * @var string|null
     * @see UserVerificationRequirement
     */
    private $userVerification;

    /**
     * @var AuthenticationExtensionsClientInputs|null
     */
    private $extensions;

    public function __construct(ByteBuffer $challenge)
    {
        $this->challenge = $challenge;
    }

    public function addAllowedCredential(PublicKeyCredentialDescriptor $credentialDescriptor)
    {
        if ($this->allowCredentials === null) {
            $this->allowCredentials = [];
        }
        $this->allowCredentials[] = $credentialDescriptor;
    }

    public function getAsArray(): array
    {
        $map = [
            'challenge' => $this->challenge,
        ];

        $map = array_merge(
            $map,
            self::removeNullValues([
                'timeout' => $this->timeout,
                'rpId' => $this->rpId,
                'allowCredentials' => $this->allowCredentials,
                'userVerification' => $this->userVerification,
                'extensions' => $this->extensions,
            ])
        );

        return $map;
    }

    /**
     * @return string|null
     */
    public function getRpId(): ?string
    {
        return $this->rpId;
    }

    /**
     * @param string|null $rpId
     */
    public function setRpId(?string $rpId): void
    {
        $this->rpId = $rpId;
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

    /**
     * @return PublicKeyCredentialDescriptor[]|null
     */
    public function getAllowCredentials(): ?array
    {
        return $this->allowCredentials;
    }

    /**
     * @return ByteBuffer
     */
    public function getChallenge(): ByteBuffer
    {
        return $this->challenge;
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
     * @return AuthenticationExtensionsClientInputs|null
     */
    public function getExtensions(): ?AuthenticationExtensionsClientInputs
    {
        return $this->extensions;
    }

    /**
     * @param AuthenticationExtensionsClientInputs|null $extensions
     */
    public function setExtensions(?AuthenticationExtensionsClientInputs $extensions): void
    {
        $this->extensions = $extensions;
    }
}
