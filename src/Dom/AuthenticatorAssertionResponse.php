<?php

namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Format\ByteBuffer;

class AuthenticatorAssertionResponse extends AbstractAuthenticatorResponse implements AuthenticatorAssertionResponseInterface
{
    /**
     * @var ByteBuffer
     */
    private $authenticatorData;

    /**
     * @var ByteBuffer
     */
    private $signature;

    /**
     * @var ByteBuffer|null
     */
    private $userHandle;

    public function __construct(string $clientDataJson, ByteBuffer $authenticatorData, ByteBuffer $signature, ?ByteBuffer $userHandle)
    {
        parent::__construct($clientDataJson);
        $this->authenticatorData = $authenticatorData;
        $this->signature = $signature;
        $this->userHandle = $userHandle;
    }

    public function getAuthenticatorData(): ByteBuffer
    {
        return $this->authenticatorData;
    }

    public function getSignature(): ByteBuffer
    {
        return $this->signature;
    }

    public function getUserHandle(): ?ByteBuffer
    {
        return $this->userHandle;
    }

    public function asAssertionResponse(): AuthenticatorAssertionResponseInterface
    {
        return $this;
    }
}
