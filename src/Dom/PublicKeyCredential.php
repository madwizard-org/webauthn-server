<?php

namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Format\ByteBuffer;

class PublicKeyCredential implements PublicKeyCredentialInterface
{
    /**
     * @var ByteBuffer
     */
    private $rawId;

    /**
     * @var AuthenticatorResponseInterface
     */
    private $response;

    /**
     * @var array
     */
    private $clientExtensionResults;

    public function __construct(ByteBuffer $rawCredentialId, AuthenticatorResponseInterface $response)
    {
        $this->rawId = $rawCredentialId;
        $this->response = $response;
    }

    public function getType(): string
    {
        return PublicKeyCredentialType::PUBLIC_KEY;
    }

    public function getRawId(): ByteBuffer
    {
        return $this->rawId;
    }

    /**
     * The credential's identifier. For public key credentials this is a base64url encoded version of the raw credential ID.
     */
    public function getId(): string
    {
        return $this->rawId->getBase64Url();
    }

    public function getResponse(): AuthenticatorResponseInterface
    {
        return $this->response;
    }

    public function setClientExtensionResults(array $extensionResults): void
    {
        $this->clientExtensionResults = $extensionResults;
    }

    /**
     * @return array Array of client extensions as provided by the client (no parsing done yet)
     */
    public function getClientExtensionResults(): array
    {
        return $this->clientExtensionResults;
    }
}
