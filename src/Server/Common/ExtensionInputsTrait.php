<?php

namespace MadWizard\WebAuthn\Server\Common;

use MadWizard\WebAuthn\Extension\ExtensionInputInterface;

trait ExtensionInputsTrait
{
    /**
     * @var ExtensionInputInterface[]
     */
    private $extensions = [];

    public function addExtensionInput(ExtensionInputInterface $input): void
    {
        $this->extensions[] = $input;
    }

    /**
     * @return ExtensionInputInterface[]
     */
    public function getExtensionInputs(): array
    {
        return $this->extensions;
    }
}
