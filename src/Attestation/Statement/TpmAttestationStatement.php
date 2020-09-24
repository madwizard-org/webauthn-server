<?php

namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Tpm\TpmAttest;
use MadWizard\WebAuthn\Attestation\Tpm\TpmPublic;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;

class TpmAttestationStatement extends AbstractAttestationStatement
{
    public const FORMAT_ID = 'tpm';

    /**
     * @var ByteBuffer
     */
    private $signature;

    /**
     * @var int
     */
    private $algorithm;

    /**
     * @var string[]|null
     */
    private $certificates;

    /**
     * @var ByteBuffer|null
     */
    private $ecdaaKeyId;

    /**
     * @var ByteBuffer
     */
    private $certInfo;

    /**
     * @var TpmAttest
     */
    private $attest;

    /**
     * @var TpmPublic
     */
    private $public;

    public function __construct(AttestationObject $attestationObject)
    {
        parent::__construct($attestationObject, self::FORMAT_ID);

        $statement = $attestationObject->getStatement();

        try {
            DataValidator::checkMap(
                $statement,
                [
                    'ver' => 'string',
                    'alg' => 'integer',
                    'ecdaaKeyId' => '?' . ByteBuffer::class,
                    'x5c' => '?array',
                    'sig' => ByteBuffer::class,
                    'certInfo' => ByteBuffer::class,
                    'pubArea' => ByteBuffer::class,
                ]
            );
        } catch (DataValidationException $e) {
            throw new ParseException('Invalid TPM attestation statement.', 0, $e);
        }

        $this->algorithm = $statement->get('alg');
        $this->signature = $statement->get('sig');

        if ($statement->get('ver') !== '2.0') {
            throw new ParseException('Only TPM version 2.0 is supported.');
        }

        $this->ecdaaKeyId = $statement->getDefault('ecdaaKeyId', null);
        $x5c = $statement->getDefault('x5c', null);

        if ($this->ecdaaKeyId === null && $x5c === null) {
            throw new ParseException('Either ecdaaKeyId or x5c must be set.');
        }
        if ($this->ecdaaKeyId !== null && $x5c !== null) {
            throw new ParseException('ecdaaKeyId and x5c cannot both be set.');
        }
        $this->certificates = $x5c === null ? null : $this->buildPEMCertificateArray($x5c);

        $this->attest = new TpmAttest($statement->get('certInfo'));
        $this->public = new TpmPublic($statement->get('pubArea'));
        $this->certInfo = $statement->get('certInfo');
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
     * @return string[]|null
     */
    public function getCertificates(): ?array
    {
        return $this->certificates;
    }

    public function getEcdaaKeyId(): ?ByteBuffer
    {
        return $this->ecdaaKeyId;
    }

    public function getRawCertInfo(): ByteBuffer
    {
        return $this->certInfo;
    }

    public function getCertInfo(): TpmAttest
    {
        return $this->attest;
    }

    public function getPubArea(): TpmPublic
    {
        return $this->public;
    }
}
