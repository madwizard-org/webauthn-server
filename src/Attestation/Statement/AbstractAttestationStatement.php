<?php


namespace MadWizard\WebAuthn\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Crypto\DER;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;

abstract class AbstractAttestationStatement implements AttestationStatementInterface
{
    /**
     * @var string
     */
    private $formatId;

    public function __construct(AttestationObject $attestationObject, string $formatId)
    {
        $actualFormat = $attestationObject->getFormat();
        if ($actualFormat !== $formatId) {
            throw new ParseException(sprintf("Not expecting format '%s' but '%s'.", $actualFormat, $formatId));
        }
        $this->formatId = $formatId;
    }

    protected function buildPEMCertificateArray(array $x5c) : array
    {
        $certificates = [];
        foreach ($x5c as $item) {
            if (!($item instanceof ByteBuffer)) {
                throw new ParseException('x5c should be array of binary data elements.');
            }
            $certificates[] = DER::pem('CERTIFICATE', $item->getBinaryString());
        }
        return $certificates;
    }

    /**
     * @return string
     */
    public function getFormatId(): string
    {
        return $this->formatId;
    }
}
