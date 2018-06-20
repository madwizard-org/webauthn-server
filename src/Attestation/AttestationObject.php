<?php


namespace MadWizard\WebAuthn\Attestation;

use MadWizard\WebAuthn\Exception\CBORException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CBOR;
use MadWizard\WebAuthn\Format\DataValidator;
use function is_array;

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
        try {
            $data = CBOR::decode($buffer);
            if (!is_array($data)) {
                throw new WebAuthnException('Expecting attestation object to be a CBOR map.');
            }

            DataValidator::checkTypes(
                $data,
                [
                    'fmt' => 'string',
                    'attStmt' => 'array',
                    'authData' => ByteBuffer::class
                ],
                false
            );

            $this->format = $data['fmt'];
            $this->statement = $data['attStmt'];
            $this->authData = $data['authData'];

            $this->data = $data;
        } catch (CBORException $e) {
            throw new WebAuthnException('Failed to parse CBOR attestation object.', 0, $e);
        }
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
