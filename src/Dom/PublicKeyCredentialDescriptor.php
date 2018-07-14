<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;

class PublicKeyCredentialDescriptor extends AbstractDictionary // TODO serializable
{
    /**
     * @var string
     */
    private $type;

    /**
     * @var ByteBuffer
     */
    private $id;

    /**
     * @var string[]
     */
    private $transports = [];

    public function __construct(ByteBuffer $credentialId, string $type = PublicKeyCredentialType::PUBLIC_KEY)
    {
        if ($type !== PublicKeyCredentialType::PUBLIC_KEY) {
            throw new WebAuthnException('Only public key accepted');
        }
        $this->type = $type;
        $this->id = $credentialId;
    }

    public function addTransport(string $transport)
    {
        // TODO:validate
        $this->transports[] = $transport;
    }

    public function getAsArray(): array
    {
        return [
            'type' => $this->type,
            'id' => $this->id,
            'transports' => $this->transports,
        ];
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return ByteBuffer
     */
    public function getId(): ByteBuffer
    {
        return $this->id;
    }

    /**
     * @return string[]
     */
    public function getTransports(): array
    {
        return $this->transports;
    }
}
