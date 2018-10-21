<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Web\Origin;

abstract class AbstractContext
{
    /**
     * @var ByteBuffer
     */
    private $challenge;

    /**
     * @var string
     */
    private $rpId;

    /**
     * @var bool
     */
    private $userVerificationRequired = false;

    /**
     * @var Origin
     */
    private $origin;

    public function __construct(ByteBuffer $challenge, Origin $origin, string $rpId)
    {
        $this->challenge = $challenge;
        $this->origin = $origin;
        $this->rpId = $rpId;
    }

    /**
     * @return ByteBuffer
     */
    public function getChallenge(): ByteBuffer
    {
        return $this->challenge;
    }

    /**
     * @return string
     */
    public function getRpId(): string
    {
        return $this->rpId;
    }

    /**
     * @return bool
     */
    public function isUserVerificationRequired(): bool
    {
        return $this->userVerificationRequired;
    }

    public function setUserVerificationRequired(bool $required): void
    {
        $this->userVerificationRequired = $required;
    }

    /**
     * @return Origin
     */
    public function getOrigin(): Origin
    {
        return $this->origin;
    }

    public function serialize()
    {
        return \serialize([$this->challenge, $this->rpId, $this->userVerificationRequired, $this->origin]);
    }

    public function unserialize($serialized)
    {
        [
            $this->challenge,
            $this->rpId,
            $this->userVerificationRequired,
            $this->origin
        ] = \unserialize((string) $serialized);
    }
}
