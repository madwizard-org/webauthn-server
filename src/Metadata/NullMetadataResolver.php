<?php


namespace MadWizard\WebAuthn\Metadata;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResult;

class NullMetadataResolver implements MetadataResolverInterface
{
    public function getMetadata(RegistrationResult $registrationResult): ?MetadataInterface
    {
        return null;
    }
}
