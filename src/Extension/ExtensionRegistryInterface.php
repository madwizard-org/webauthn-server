<?php

namespace MadWizard\WebAuthn\Extension;

interface ExtensionRegistryInterface
{
    public function getExtension(string $extensionId): ExtensionInterface;
}
