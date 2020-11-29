<?php

namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\DataValidator;
use MadWizard\WebAuthn\Pki\X509Certificate;

class AppleAttestationStatement extends AbstractAttestationStatement
{
    public const FORMAT_ID = 'apple';

    /**
     * @var X509Certificate[]
     */
    private $certificates;

    public function __construct(AttestationObject $attestationObject)
    {
        parent::__construct($attestationObject, self::FORMAT_ID);

        // See https://webkit.org/blog/11312/meet-face-id-and-touch-id-for-the-web/

        $statement = $attestationObject->getStatement();

        // Note: early iOS versions included an 'alg' parameter which was removed later
        try {
            DataValidator::checkMap(
                $statement,
                [
                    'x5c' => 'array',
                ],
                false
            );
        } catch (DataValidationException $e) {
            throw new ParseException('Invalid apple attestation statement.', 0, $e);
        }

        $x5c = $statement->get('x5c');
        $this->certificates = $this->buildPEMCertificateArray($x5c);
    }

    /**
     * @return X509Certificate[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }
}
