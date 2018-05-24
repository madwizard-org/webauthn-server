<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use function json_last_error;

abstract class AbstractAuthenticatorResponse implements AuthenticatorResponseInterface
{
    /**
     * @var string
     */
    private $clientDataJSON;

    private $parsedJson;

    public function __construct(string $clientDataJSON)
    {
        $data = \json_decode($clientDataJSON, true, 10);
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new WebAuthnException('Unparseable client data JSON');
        }
        if (!\is_array($data)) {
            throw new WebAuthnException('Expected object for client data');
        }
        $this->parsedJson = $data;
        $this->clientDataJSON = $clientDataJSON;
    }

    public function getClientDataJSON(): string
    {
        return $this->clientDataJSON;
    }

    public function getParsedClientData() : array
    {
        return $this->parsedJson;
    }
}
