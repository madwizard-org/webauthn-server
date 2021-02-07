<?php

namespace MadWizard\WebAuthn\Metadata\Provider\Apple;

use MadWizard\WebAuthn\Attestation\Statement\AppleAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Metadata\Provider\MetadataProviderInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

final class AppleDevicesProvider implements MetadataProviderInterface
{
    public function getMetadata(RegistrationResultInterface $registrationResult): ?MetadataInterface
    {
        // NOTE: Apple always used a zero AAGUID but has changed this to a specific AAGUID later, which might be
        // resolved using a metadata service.
        if ($registrationResult->getAttestationObject()->getFormat() === AppleAttestationStatement::FORMAT_ID) {
            return new AppleDeviceMetadata();
        }
        return null;
    }

    public function getDescription(): string
    {
        return 'Apple devices metadata provider';
    }
}
