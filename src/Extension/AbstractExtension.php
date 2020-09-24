<?php

namespace MadWizard\WebAuthn\Extension;

use MadWizard\WebAuthn\Exception\WebAuthnException;

abstract class AbstractExtension implements ExtensionInterface
{
    /**
     * @var string
     */
    private $identifier;

    /**
     * @var string[]
     */
    private $supportedOperations;

    public function __construct(string $identifier, array $supportedOperations)
    {
        $this->identifier = $identifier;

        if (!ExtensionHelper::validExtensionIdentifier($identifier)) {
            throw new WebAuthnException(sprintf("Invalid extension identifier '%s'.", $identifier));
        }
        $this->supportedOperations = $supportedOperations;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getSupportedOperations(): array
    {
        return $this->supportedOperations;
    }
}
