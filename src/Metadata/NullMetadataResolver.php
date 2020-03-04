<?php


namespace MadWizard\WebAuthn\Metadata;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResult;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

class NullMetadataResolver implements MetadataResolverInterface
{
    public function getMetadata(RegistrationResultInterface $registrationResult): ?MetadataInterface
    {
        return null;
    }
}
