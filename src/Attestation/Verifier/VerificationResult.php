<?php

namespace MadWizard\WebAuthn\Attestation\Verifier;

use InvalidArgumentException;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;

final class VerificationResult
{
    /**
     * @var string
     */
    private $type;

    /**
     * @var TrustPathInterface
     */
    private $trustPath;

    /**
     * @param string $type Attestation type (see AttestationType for type enumeration)
     *
     * @see AttestationType
     */
    public function __construct(string $type, TrustPathInterface $trustPath)
    {
        if (!AttestationType::isValidType($type)) {
            throw new InvalidArgumentException(sprintf('Type "%s" is not a valid attestation type.', $type));
        }
        $this->type = $type;
        $this->trustPath = $trustPath;
    }

    public function getAttestationType(): string
    {
        return $this->type;
    }

    public function getTrustPath(): TrustPathInterface
    {
        return $this->trustPath;
    }
}
