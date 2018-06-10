<?php


namespace MadWizard\WebAuthn\Dom;

use InvalidArgumentException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use Serializable;

class PublicKeyCredentialRequestOptions extends AbstractDictionary implements Serializable
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
     * @var null|PublicKeyCredentialDescriptor[]
     */
    private $allowCredentials;

    /**
     * @var string|null
     */
    private $userVerification;

    /**
     * @var AuthenticationExtensionsClientInputs[]
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

        if ($this->timeout !== null) {
            $map['timeout'] = $this->timeout;
        }

        if ($this->rpId !== null) {
            $map['rpId'] = $this->rpId;
        }

        if ($this->allowCredentials !== null) {
            foreach ($this->allowCredentials as $credential) {
                $map['allowCredentials'][] = $credential->getAsArray();
            }
        }
        if ($this->userVerification !== null) {
            $map['userVerification'] = $this->userVerification;
        }

        if ($this->extensions !== null) {
            //$map['extensions'] = $this->extensions;
        }
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
     * @param string $rpId
     */
    public function setRpId(string $rpId): void
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
            throw new InvalidArgumentException(sprintf('Value %s is not a valid UserVerificationRequirement', $value));
        }

        $this->userVerification = $value;
    }

    public function serialize()
    {
        return serialize([
            'challenge' => $this->challenge,
            'timeout' => $this->timeout,
            'rpId' => $this->rpId,
            'allowCredentials' => $this->allowCredentials,
            'userVerification' => $this->userVerification,
            'extensions' => $this->extensions,
        ]);
    }

    public function unserialize($serialized)
    {
        $arr = \unserialize($serialized);
        $this->challenge = $arr['challenge'];
        $this->timeout = $arr['timeout'];
        $this->rpId = $arr['rpId'];
        $this->allowCredentials = $arr['allowCredentials'];
        $this->userVerification = $arr['userVerification'];
        $this->extensions = $arr['extensions'];
    }
}
