<?php


namespace MadWizard\WebAuthn\Metadata;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResult;

interface MetadataResolverInterface // TODO move namespace
{
    public function getMetadata(RegistrationResult $registrationResult) : ?MetadataInterface;
}
