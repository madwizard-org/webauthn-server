<?php

namespace MadWizard\WebAuthn\Attestation\Registry;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Statement\UnsupportedAttestationStatement;
use MadWizard\WebAuthn\Attestation\Verifier\AttestationVerifierInterface;
use MadWizard\WebAuthn\Attestation\Verifier\UnsupportedAttestationVerifier;
use MadWizard\WebAuthn\Exception\FormatNotSupportedException;

final class AttestationFormatRegistry implements AttestationFormatRegistryInterface
{
    /**
     * @var AttestationFormatInterface[]
     */
    private $formats = [];

    /**
     * @var bool
     */
    private $strictSupportedFormats = true;

    public function __construct()
    {
    }

    public function addFormat(AttestationFormatInterface $format): void
    {
        $this->formats[$format->getFormatId()] = $format;
    }

    public function createStatement(AttestationObject $attestationObject): AttestationStatementInterface
    {
        $formatId = $attestationObject->getFormat();
        $format = $this->formats[$formatId] ?? null;
        if ($format === null) {
            if ($this->strictSupportedFormats) {
                throw new FormatNotSupportedException(sprintf('Format "%s" is not supported.', $formatId));
            }
            return new UnsupportedAttestationStatement($attestationObject);
        }
        return $format->createStatement($attestationObject);
    }

    public function getVerifier(string $formatId): AttestationVerifierInterface
    {
        $format = $this->formats[$formatId] ?? null;
        if ($format === null) {
            if ($this->strictSupportedFormats) {
                throw new FormatNotSupportedException(sprintf('Format "%s" is not supported.', $formatId));
            }
            return new UnsupportedAttestationVerifier();
        }
        return $format->getVerifier();
    }

    public function strictSupportedFormats(bool $strict): void
    {
        $this->strictSupportedFormats = $strict;
    }
}
