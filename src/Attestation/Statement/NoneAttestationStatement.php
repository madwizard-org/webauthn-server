<?php


namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObjectInterface;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInAttestationFormat;
use MadWizard\WebAuthn\Attestation\Verifier\NoneAttestationVerifier;
use MadWizard\WebAuthn\Exception\ParseException;

class NoneAttestationStatement extends AbstractAttestationStatement
{
    public const FORMAT_ID = 'none';

    public function __construct(AttestationObjectInterface $attestationObject)
    {
        parent::__construct($attestationObject, self::FORMAT_ID);

        $statement = $attestationObject->getStatement();
        if (\count($statement) !== 0) {
            throw new ParseException("Expecting empty map for 'none' attestation statement.");
        }
    }

    public static function createFormat() : AttestationFormatInterface
    {
        return new BuiltInAttestationFormat(
            self::FORMAT_ID,
            self::class,
            NoneAttestationVerifier::class
        );
    }
}
