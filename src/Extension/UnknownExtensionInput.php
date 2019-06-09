<?php


namespace MadWizard\WebAuthn\Extension;

class UnknownExtensionInput extends AbstractExtensionInput
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
