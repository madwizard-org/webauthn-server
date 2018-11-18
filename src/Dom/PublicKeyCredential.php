<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\UnsupportedException;
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
     * The credential's identifier. For public key credentials this is a base64url encoded version of the raw credential ID.
     * @return string
     */
    public function getId(): string
    {
        return $this->rawId->getBase64Url();
    }

    public function getResponse(): AuthenticatorResponseInterface
    {
        return $this->response;
    }

    // TODO
    public function getClientExtensionResults(): array
    {
        throw new UnsupportedException('Client extensions are not supported yet');
    }
}
