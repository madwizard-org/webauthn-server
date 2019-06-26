<?php


namespace MadWizard\WebAuthn\Extension;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use function sprintf;

abstract class AbstractExtensionOutput implements ExtensionOutputInterface
{
    /**
     * @var string
     */
    private $identifier;

    /**
     * @var mixed
     */
    protected $output;

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;

        if (!ExtensionHelper::validExtensionIdentifier($identifier)) {
            throw new WebAuthnException(sprintf("Invalid extension identifier '%s'.", $identifier));
        }
    }

    /**
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @return mixed
     */
    public function getOutput()
    {
        return $this->output;
    }
}
