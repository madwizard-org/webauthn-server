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

    public function __construct(string $clientDataJSON)
    {
        $data = \json_decode($clientDataJSON, true, 10);
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new WebAuthnException('Unparseable client data JSON');
        }
        $this->clientDataJSON = $clientDataJSON;
    }

    public function getClientDataJSON(): string
    {
        return $this->clientDataJSON;
    }
}
