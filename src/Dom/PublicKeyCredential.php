<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\WebAuthnException;
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
     * The credential's identifier. For public key credentials this is a base64 encoded version of the raw credential ID.
     * @return string
     */
    public function getId(): string
    {
        return \base64_encode($this->rawId->getBinaryString());
    }

    public function getResponse(): AuthenticatorResponseInterface
    {
        return $this->response;
    }

    // TODO
    public function getClientExtensionResults(): array
    {
        throw new WebAuthnException('TODO: Client extensions nor supported yet');
    }
}
