<?php


namespace MadWizard\WebAuthn\Metadata\Source;

use MadWizard\WebAuthn\Attestation\Identifier\IdentifierInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;

interface MetadataSourceInterface
{
    public function getMetadata(IdentifierInterface $identifier) : ?MetadataInterface;
}
