<?php

namespace MadWizard\WebAuthn\Metadata;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

interface MetadataResolverInterface // TODO move namespace
{
    public function getMetadata(RegistrationResultInterface $registrationResult): ?MetadataInterface;
}
