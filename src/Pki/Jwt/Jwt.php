<?php

namespace MadWizard\WebAuthn\Pki\Jwt;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;

class Jwt implements JwtInterface
{
    /**
     * @var array
     */
    private $header;

    /**
     * @var array
     */
    private $body;

    /**
     * @var ByteBuffer
     */
    private $signedData;

    /**
     * @var ByteBuffer
     */
    private $signature;

    public function __construct(string $token)
    {
        $parts = explode('.', $token);
        [$headerJson, $bodyJson, $signature] = self::decodeToken($parts);

        $header = self::jsonDecode($headerJson);
        $body = self::jsonDecode($bodyJson);

        if (!is_array($header)) {
            throw new ParseException('Expecting header to be a json object.');
        }

        if (!is_array($body)) {
            throw new ParseException('Expecting body to be a json object.');
        }

        $this->header = $header;
        $this->body = $body;
        $this->signedData = new ByteBuffer($parts[0] . '.' . $parts[1]);
        $this->signature = new ByteBuffer($signature);
    }

    private static function decodeToken(array $parts): array
    {
        if (count($parts) !== 3) {
            throw new ParseException('Invalid JWT');
        }

        return [
            Base64UrlEncoding::decode($parts[0]),
            Base64UrlEncoding::decode($parts[1]),
            Base64UrlEncoding::decode($parts[2]),
        ];
    }

    private static function jsonDecode(string $json): array
    {
        $decoded = json_decode($json, true);
        if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new ParseException(sprintf('JSON parse error in JWT: %s.', json_last_error_msg()));
        }
        return $decoded;
    }

    public function getHeader(): array
    {
        return $this->header;
    }

    public function getBody(): array
    {
        return $this->body;
    }

    public function getSignedData(): ByteBuffer
    {
        return $this->signedData;
    }

    public function getSignature(): ByteBuffer
    {
        return $this->signature;
    }
}
