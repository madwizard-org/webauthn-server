<?php

namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;

class AndroidSafetyNetAttestationStatement extends AbstractAttestationStatement
{
    public const FORMAT_ID = 'android-safetynet';

    /**
     * @var string
     */
    private $response;

    /**
     * @var string
     */
    private $version;

    public function __construct(AttestationObject $attestationObject)
    {
        parent::__construct($attestationObject, self::FORMAT_ID);

        $statement = $attestationObject->getStatement();

        try {
            DataValidator::checkMap(
                $statement,
                [
                    'ver' => 'string',
                    'response' => ByteBuffer::class,
                ]
            );
        } catch (DataValidationException $e) {
            throw new ParseException('Invalid Android SafetyNet attestation statement.', 0, $e);
        }

        $this->version = $statement->get('ver');
        if ($this->version === '') {
            throw new ParseException('Android SafetyNet version is empty.');
        }

        $res = $statement->get('response');
        assert($res instanceof ByteBuffer);
        $this->response = $res->getBinaryString();
    }

    public function getVersion(): string
    {
        return $this->version;
    }

    public function getResponse(): string
    {
        return $this->response;
    }
}
