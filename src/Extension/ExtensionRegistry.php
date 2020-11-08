<?php

namespace MadWizard\WebAuthn\Extension;

use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Exception\UnsupportedException;

class ExtensionRegistry implements ExtensionRegistryInterface
{
    /**
     * @var array<string, ExtensionInterface>
     */
    private $extensions = [];

    public function __construct()
    {
    }

    public function addExtension(ExtensionInterface $extension): void
    {
        $id = $extension->getIdentifier();
        if (isset($this->extensions[$id])) {
            throw new ConfigurationException(sprintf('Extension with identifier %s is already registered.', $id));
        }
        $this->extensions[$id] = $extension;
    }

    public function getExtension(string $extensionId): ExtensionInterface
    {
        $ext = $this->extensions[$extensionId] ?? null;
        if ($ext === null) {
            throw new UnsupportedException(sprintf('Extension with id %s not supported.', $extensionId));
        }
        return $ext;
    }
}
