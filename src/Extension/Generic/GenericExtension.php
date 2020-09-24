<?php

namespace MadWizard\WebAuthn\Extension\Generic;

use MadWizard\WebAuthn\Extension\AbstractExtension;
use MadWizard\WebAuthn\Extension\ExtensionInputInterface;
use MadWizard\WebAuthn\Extension\ExtensionOutputInterface;
use MadWizard\WebAuthn\Extension\ExtensionProcessingContext;
use MadWizard\WebAuthn\Extension\ExtensionResponseInterface;

class GenericExtension extends AbstractExtension
{
    public function __construct(string $identifier, array $supportedOperations)
    {
        parent::__construct($identifier, $supportedOperations);
    }

    public function parseResponse(ExtensionResponseInterface $extensionResponse): ExtensionOutputInterface
    {
        return new GenericExtensionOutput($extensionResponse);
    }

    public function processExtension(ExtensionInputInterface $input, ExtensionOutputInterface $output, ExtensionProcessingContext $context): void
    {
        // No action
    }
}
