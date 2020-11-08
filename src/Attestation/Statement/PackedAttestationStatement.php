<?php

namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;
use MadWizard\WebAuthn\Pki\X509Certificate;

class PackedAttestationStatement extends AbstractAttestationStatement
{
    public const FORMAT_ID = 'packed';

    /**
     * @var ByteBuffer
     */
    private $signature;

    /**
     * @var int
     */
    private $algorithm;

    /**
     * @var X509Certificate[]|null
     */
    private $certificates;

    /**
     * @var ByteBuffer|null
     */
    private $ecdaaKeyId;

    public function __construct(AttestationObject $attestationObject)
    {
        parent::__construct($attestationObject, self::FORMAT_ID);

        $statement = $attestationObject->getStatement();

        try {
            DataValidator::checkMap(
                $statement,
                [
                    'alg' => 'integer',
                    'sig' => ByteBuffer::class,
                    'x5c' => '?array',
                    'ecdaaKeyId' => '?' . ByteBuffer::class,
                ]
            );
        } catch (DataValidationException $e) {
            throw new ParseException('Invalid packed attestation statement.', 0, $e);
        }

        $this->algorithm = $statement->get('alg');
        $this->signature = $statement->get('sig');

        $this->ecdaaKeyId = $statement->getDefault('ecdaaKeyId', null);
        $x5c = $statement->getDefault('x5c', null);

        if ($this->ecdaaKeyId !== null && $x5c !== null) {
            throw new ParseException('ecdaaKeyId and x5c cannot both be set.');
        }
        $this->certificates = $x5c === null ? null : $this->buildPEMCertificateArray($x5c);
    }

    public function getSignature(): ByteBuffer
    {
        return $this->signature;
    }

    public function getAlgorithm(): int
    {
        return $this->algorithm;
    }

    /**
     * @return X509Certificate[]|null
     */
    public function getCertificates(): ?array
    {
        return $this->certificates;
    }

    public function getEcdaaKeyId(): ?ByteBuffer
    {
        return $this->ecdaaKeyId;
    }
}
