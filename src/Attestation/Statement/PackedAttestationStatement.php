<?php

namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInAttestationFormat;
use MadWizard\WebAuthn\Attestation\Verifier\PackedAttestationVerifier;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;

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
     * @var string[]|null
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
            DataValidator::checkTypes(
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

        $this->algorithm = $statement['alg'];
        $this->signature = $statement['sig'];

        $this->ecdaaKeyId = $statement['ecdaaKeyId'] ?? null;
        $x5c = $statement['x5c'] ?? null;

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

    public static function createFormat(): AttestationFormatInterface
    {
        return new BuiltInAttestationFormat(
            self::FORMAT_ID,
            self::class,
            PackedAttestationVerifier::class
        );
    }
}
