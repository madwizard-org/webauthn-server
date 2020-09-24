<?php

namespace MadWizard\WebAuthn\Extension\Generic;

use MadWizard\WebAuthn\Extension\AbstractExtensionInput;

class GenericExtensionInput extends AbstractExtensionInput
{
    public function __construct(string $identifier, $input = null)
    {
        parent::__construct($identifier);
        $this->input = $input;
    }

    /**
     * @param mixed $input
     */
    public function setInput($input): void
    {
        $this->input = $input;
    }
}
