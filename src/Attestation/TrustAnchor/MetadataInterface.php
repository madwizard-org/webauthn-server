<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Metadata\Statement\StatusReport;

interface MetadataInterface
{
    /**
     * @return TrustAnchorInterface[]
     */
    public function getTrustAnchors(): array;

    /**
     * @param string $type
     * @see AttestationType
     * @return bool
     */
    public function supportsAttestationType(string $type): bool;

    /**
     * @return StatusReport[]
     */
    public function getStatusReports(): array;
}
