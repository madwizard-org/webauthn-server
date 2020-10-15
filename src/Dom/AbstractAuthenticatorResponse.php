<?php

namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use function json_last_error;

abstract class AbstractAuthenticatorResponse implements AuthenticatorResponseInterface
{
    public const UTF8_BOM = "\xEF\xBB\xBF";

    /**
     * @var string
     */
    private $clientDataJson;

    /**
     * @var CollectedClientData
     */
    private $clientData;

    public function __construct(string $clientDataJson)
    {
        $this->clientDataJson = $clientDataJson;

        // Specification says to remove the UTF-8 byte order mark, if any
        if (\substr($clientDataJson, 0, 3) === self::UTF8_BOM) {
            $clientDataJson = substr($clientDataJson, 3);
        }
        $data = \json_decode($clientDataJson, true, 10);
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new ParseException('Unparseable client data JSON');
        }
        if (!\is_array($data)) {
            throw new ParseException('Expected object for client data');
        }
        $this->clientData = CollectedClientData::fromJson($data);
    }

    public function getClientDataJson(): string
    {
        return $this->clientDataJson;
    }

    public function getParsedClientData(): CollectedClientData
    {
        return $this->clientData;
    }

    public function asAttestationResponse(): AuthenticatorAttestationResponseInterface
    {
        throw new WebAuthnException('Response is not an attestation response.');
    }

    public function asAssertionResponse(): AuthenticatorAssertionResponseInterface
    {
        throw new WebAuthnException('Response is not an assertion response.');
    }
}
