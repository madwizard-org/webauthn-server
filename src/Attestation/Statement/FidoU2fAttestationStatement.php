<?php


namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;

class FidoU2fAttestationStatement extends AbstractAttestationStatement
{
    public const FORMAT_ID = 'fido-u2f';

    /**
     * @var ByteBuffer
     */
    private $signature;

    /**
     * @var string[]
     */
    private $certificates;

    public function __construct(AttestationObject $attestationObject)
    {
        parent::__construct($attestationObject, self::FORMAT_ID);

        $statement = $attestationObject->getStatement();

        try {
            DataValidator::checkTypes(
                $statement,
                [
                    'x5c' => 'array',
                    'sig' => ByteBuffer::class,
                ]
            );
        } catch (DataValidationException $e) {
            throw new ParseException('Invalid FIDO U2F attestation statement.', 0, $e);
        }

        $sig = $statement['sig'];
        $x5c = $statement['x5c'];

        $this->signature = $sig;
        $this->certificates = $this->buildPEMCertificateArray($x5c);
    }

    /**
     * @return ByteBuffer
     */
    public function getSignature(): ByteBuffer
    {
        return $this->signature;
    }

    /**
     * @return string[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }
}
