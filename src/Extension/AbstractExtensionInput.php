<?php

namespace MadWizard\WebAuthn\Extension;

use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\SerializableTrait;
use function sprintf;

abstract class AbstractExtensionInput implements ExtensionInputInterface
{
    use SerializableTrait;

    /**
     * @var string
     */
    private $identifier;

    /**
     * @var mixed // TODO stricter type?
     */
    protected $input;

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;

        if (!ExtensionHelper::validExtensionIdentifier($identifier)) {
            throw new WebAuthnException(sprintf("Invalid extension identifier '%s'.", $identifier));
        }
    }

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

    public function __serialize(): array
    {
        return ['id' => $this->identifier, 'input' => $this->input];
    }

    public function __unserialize(array $data): void
    {
        $this->identifier = $data['id'];
        $this->input = $data['input'];
    }
}
