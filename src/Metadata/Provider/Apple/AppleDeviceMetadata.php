<?php

namespace MadWizard\WebAuthn\Metadata\Provider\Apple;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\TrustAnchor\CertificateTrustAnchor;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Pki\X509Certificate;
use MadWizard\WebAuthn\Util\BundledData;

final class AppleDeviceMetadata implements MetadataInterface
{
    public function getTrustAnchors(): array
    {
        return [
            new CertificateTrustAnchor(X509Certificate::fromPem(BundledData::getContents('apple/apple-webauthn-root.crt'))),
        ];
    }

    public function supportsAttestationType(string $type): bool
    {
        return $type === AttestationType::ANON_CA;
    }

    public function getStatusReports(): array
    {
        return [];
    }

    public function getDescription(): string
    {
        return 'Apple device (Touch ID / Face ID)';
    }
}
