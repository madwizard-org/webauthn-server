<?php

namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\SerializableTrait;
use MadWizard\WebAuthn\Web\Origin;

abstract class AbstractContext  // TODO: use composition instead of inheritance
{
    use SerializableTrait;

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
     * @var bool
     */
    private $userPresenceRequired = true;

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

    public function getChallenge(): ByteBuffer
    {
        return $this->challenge;
    }

    public function getRpId(): string
    {
        return $this->rpId;
    }

    public function isUserVerificationRequired(): bool
    {
        return $this->userVerificationRequired;
    }

    public function setUserVerificationRequired(bool $required): void
    {
        $this->userVerificationRequired = $required;
    }

    public function isUserPresenceRequired(): bool
    {
        return $this->userPresenceRequired;
    }

    public function setUserPresenceRequired(bool $required): void
    {
        $this->userPresenceRequired = $required;
    }

    public function getOrigin(): Origin
    {
        return $this->origin;
    }

    public function __serialize(): array
    {
        return [
            'challenge' => $this->challenge,
            'rpId' => $this->rpId,
            'userVerificationRequired' => $this->userVerificationRequired,
            'origin' => $this->origin,
            'userPresenceRequired' => $this->userPresenceRequired,
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->challenge = $data['challenge'];
        $this->rpId = $data['rpId'];
        $this->userVerificationRequired = $data['userVerificationRequired'];
        $this->origin = $data['origin'];
        $this->userPresenceRequired = $data['userPresenceRequired'];
    }
}
