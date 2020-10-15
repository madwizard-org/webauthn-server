<?php

namespace MadWizard\WebAuthn\Metadata\Provider;

use MadWizard\WebAuthn\Attestation\Identifier\IdentifierInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

interface MetadataProviderInterface
{
    /**
     * @throws WebAuthnException
     */
    public function getMetadata(IdentifierInterface $identifier, RegistrationResultInterface $registrationResult): ?MetadataInterface;

    public function getDescription(): string;
}
