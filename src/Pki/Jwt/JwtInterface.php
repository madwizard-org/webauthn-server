<?php

namespace MadWizard\WebAuthn\Pki\Jwt;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface JwtInterface
{
    public const ES_AND_RSA = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512'];

    /**
     * @return array
     */
    public function getHeader(): array;

    /**
     * @return array
     */
    public function getBody(): array;

    /**
     * @return ByteBuffer
     */
    public function getSignedData(): ByteBuffer;

    /**
     * @return ByteBuffer
     */
    public function getSignature(): ByteBuffer;
}
