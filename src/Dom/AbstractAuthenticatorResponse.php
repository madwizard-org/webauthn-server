<?php


namespace MadWizard\WebAuthn\Dom;

use MadWizard\WebAuthn\Exception\ParseException;
use function json_last_error;

abstract class AbstractAuthenticatorResponse implements AuthenticatorResponseInterface
{
    const UTF8_BOM = "\xEF\xBB\xBF";

    /**
     * @var string
     */
    private $clientDataJson;

    private $parsedJson;

    public function __construct(string $clientDataJson)
    {
        $this->clientDataJson = $clientDataJson;

        // Specification says to remove the UTF-8 byte order mark, if any
        // TODO: should hash include BOM or not?
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
        $this->parsedJson = $data;
    }

    public function getClientDataJson(): string
    {
        return $this->clientDataJson;
    }

    public function getParsedClientData() : array
    {
        return $this->parsedJson;
    }
}
