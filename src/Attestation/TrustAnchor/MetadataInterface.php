<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\AttestationType;

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

    public function getStatusReports(): array; // TODO: types
}
