<?php


namespace MadWizard\WebAuthn\Extension;

class UnknownExtensionOutput extends AbstractExtensionOutput
{
    public function __construct(string $identifier, $output = null)
    {
        parent::__construct($identifier);
        $this->output = $output;
    }

    /**
     * @param mixed $output
     */
    public function setOutput($output): void
    {
        $this->output = $output;
    }
}
