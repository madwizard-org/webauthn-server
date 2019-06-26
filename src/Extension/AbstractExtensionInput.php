<?php


namespace MadWizard\WebAuthn\Extension;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use function sprintf;

abstract class AbstractExtensionInput implements ExtensionInputInterface
{
    /**
     * @var string
     */
    private $identifier;

    /**
     * @var mixed
     */
    protected $input;

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
    public function getInput()
    {
        return $this->input;
    }
}
