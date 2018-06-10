<?php


namespace MadWizard\WebAuthn\Attestation;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CBOR;
use function is_array;
use function is_string;

class AttestationObject
{
    /**
     * @var array
     */
    private $data;

    /**
     * @var string
     */
    private $format;

    /**
     * @var array
     */
    private $statement;

    /**
     * @var ByteBuffer
     */
    private $authData;

    public function __construct(ByteBuffer $buffer)
    {
        $data = CBOR::decode($buffer);
        if (!is_array($data)) {
            throw new WebAuthnException('Expecting attestation object to be a CBOR map.');
        }

        $format = $data['fmt'] ?? null;

        if (!is_string($format)) {
            throw new WebAuthnException("Expecting 'fmt' key to be a string value.");
        }

        $this->format = $format;

        $statement = $data['attStmt'] ?? null;
        if (!is_array($statement)) {
            throw new WebAuthnException("Expecting 'attStmt' key to be a CBOR map.");
        }
        $this->statement = $statement;

        $authData = $data['authData'] ?? null;
        if (!($authData instanceof ByteBuffer)) {
            throw new WebAuthnException("Expecting 'authData' key to be a CBOR byte array.");
        }
        $this->authData = $authData;

        $this->data = $data;
    }

    public function getFormat(): string
    {
        return $this->format;
    }

    public function getStatement() : array
    {
        return $this->statement;
    }

    /**
     * @return ByteBuffer
     */
    public function getAuthenticatorData(): ByteBuffer
    {
        return $this->authData;
    }
}
